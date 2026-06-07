# Technique 05 — BYOVD: WinDivert / EDRPrison

## Overview

**EDRPrison** is an EDR silencing tool that leverages **WinDivert** — a legitimate,
open-source, signed network packet capture driver — to intercept and drop network
packets originating from identified EDR processes at the NDIS packet level.

This approach differs from WFP filter injection because it operates at a lower layer
(packet level, not connection-establishment level) and avoids calling sensitive APIs
like `OpenProcess` on EDR processes.

**Tool:** [EDRPrison](https://github.com/senzee1984/EDRPrison)  
**Driver leveraged:** WinDivert (WinDivert64.sys) — valid Microsoft-compatible signature  
**Layer:** Between NDIS and TCP/IP stack (packet intercept)  
**Blog post:** `https://www.3nailsinfosec.com/post/edrprison-borrow-a-legitimate-driver-to-mute-edr-agent`

---

## What Is WinDivert?

WinDivert is an open-source Windows packet interception library. It installs a kernel
driver (`WinDivert64.sys`) that:
- Hooks into the NDIS network stack
- Intercepts inbound and outbound packets before they reach the application
- Exposes them to user-mode via `WinDivertRecv()` / `WinDivertSend()`
- Allows user-mode to drop packets by simply not re-injecting them

WinDivert is legitimately used in VPN software, firewalls, and network testing tools.
Its driver is signed and can be loaded on most Windows configurations.

---

## How EDRPrison Works

### Step 1: Identify EDR Processes

EDRPrison maintains a hardcoded list of known EDR process names:
```c
const WCHAR *edrProcesses[] = {
    L"MsMpEng.exe",     // Windows Defender
    L"MsSense.exe",     // MDE Sense
    L"elastic-agent.exe",
    L"xagt.exe",        // FireEye/Trellix
    L"csfalconservice.exe", // CrowdStrike
    // ... more
};
```

It enumerates running processes to collect PIDs of matching processes.

### Step 2: Install WinDivert Driver

```c
HANDLE hDivert = WinDivertOpen(
    "outbound",     // direction: outbound packets
    WINDIVERT_LAYER_NETWORK,
    0,              // priority
    0               // flags
);
```

WinDivert opens a handle that intercepts **all** outbound network packets at the
network layer before they reach the NIC.

### Step 3: Intercept Packets and Check PID

The key insight: WinDivert provides `WINDIVERT_ADDRESS` metadata for each intercepted
packet, which includes the originating **process ID**.

```c
WINDIVERT_ADDRESS addr;
BYTE packet[65535];
UINT packetLen;

while (TRUE) {
    // Receive next intercepted packet
    WinDivertRecv(hDivert, packet, sizeof(packet), &packetLen, &addr);

    // Check if the packet came from an EDR process
    DWORD pid = addr.Network.IfIdx;  // simplified; actual field varies by version

    if (IsEdrPid(pid)) {
        // Drop the packet — do NOT call WinDivertSend
        // Packet is simply discarded
        continue;
    }

    // Re-inject non-EDR packets
    WinDivertSend(hDivert, packet, packetLen, NULL, &addr);
}
```

Because EDR packets are intercepted and never re-injected, the EDR process appears
to successfully send data (no socket error), but the packet never reaches the network.
This avoids socket-level errors that might trigger EDR self-healing.

### Step 4: Cleanup

```c
WinDivertClose(hDivert);
// WinDivert uninstalls its hook
```

---

## Advantage Over EDRSilencer

| Aspect | EDRSilencer | EDRPrison |
|---|---|---|
| API used to get EDR path | `OpenProcess` + `QueryFullProcessImageName` | `WinDivert addr.ProcessId` (no handle to EDR) |
| WFP filter created? | Yes — visible in WFP filter list | No WFP filter added |
| EDR sees connection failure | Yes (immediate WSAEACCES) | No (packet silently dropped) |
| Windows Event 5447 | Yes | No |
| Detectable? | Via Event 5447, WFPExplorer | Via WinDivert driver presence |

The lack of `OpenProcess` on EDR processes is significant because many EDRs monitor
for attempts to open handles to their own process.

---

## Packet-Level vs Connection-Level Blocking

```
EDRSilencer blocks at:  FWPM_LAYER_ALE_AUTH_CONNECT
                        ↑ Connection initiation (before TCP handshake)
                        EDR sees WSAEACCES immediately

EDRPrison blocks at:    NDIS network layer
                        ↑ Individual packets, after connection "succeeds"
                        EDR sees successful send() but no data arrives
                        No socket error is generated
```

The silent drop behavior makes EDRPrison harder for an EDR to self-diagnose — the
EDR thinks it is connected and transmitting, but no data arrives at the C2.

---

## Limitations

### 1. WinDivert Driver on Disk

The driver file `WinDivert64.sys` must be present. Modern EDRs scan for known tool
driver names. It can be renamed/obfuscated, but hash signatures exist.

### 2. Driver Load Event

Loading WinDivert generates:
- Service Control Manager event 7045 (new service installed)
- Windows Security event (if auditing driver load)

### 3. WFPExplorer / Callout Visibility

WinDivert registers a WFP callout (it needs to hook into the network stack). Tools
like WFPExplorer will show the callout registration, even if no user-visible filters
are added.

### 4. CPU Overhead

Intercepting and examining every outbound packet (to check PID) has measurable CPU
overhead compared to connection-level blocking in WFP. For high-traffic machines,
this difference is noticeable.

---

## Detection

| Artifact | Details |
|---|---|
| WinDivert64.sys on disk | Hash or name match |
| Event 7045 | Service "WinDivert" installed |
| WFPExplorer callout entry | `WinDivert` callout in WFP callout list |
| Elastic detection rule | Rules exist specifically for WinDivert-based EDR blocking |
| Driver signature check | `WinDivert64.sys` has known certificate; unexpected load context |

---

## Defensive Recommendations

1. Block `WinDivert64.sys` hash via Application Control (WDAC) policies
2. Alert on unexpected Service creation (Event 7045) for network drivers
3. Enumerate WFP callouts periodically and alert on unknown callout GUIDs
4. Use EDR processes protected by PPL or kernel callbacks that detect network disruption

---

## References

- EDRPrison GitHub: `https://github.com/senzee1984/EDRPrison`
- 3nails blog: `https://www.3nailsinfosec.com/post/edrprison-borrow-a-legitimate-driver-to-mute-edr-agent`
- WinDivert official: `https://reqrypt.org/windivert.html`

---

Next: `06_qos-throttling-edrchoker.md`

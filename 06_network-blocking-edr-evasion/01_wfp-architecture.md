# Windows Filtering Platform (WFP) — Architecture Deep Dive

## What Is WFP?

Windows Filtering Platform (WFP) is a kernel-mode framework introduced in Windows Vista
that provides a general-purpose packet filtering infrastructure. It replaced older
mechanisms like:
- NDIS hooking (patching NDIS.sys function pointers in memory)
- Winsock SPI (LSP) hooking
- TDI (Transport Driver Interface) filtering

WFP is used by Windows Firewall, many antivirus/EDR products, VPN clients, and network
monitoring tools.

---

## The Windows Network Stack

Traffic flows through these layers (top = user space, bottom = hardware):

```
┌─────────────────────────────────────────────────┐
│          User-mode Applications                  │
├─────────────────────────────────────────────────┤
│          Winsock (ws2_32.dll)                    │
├─────────────────────────────────────────────────┤
│          AFD.sys  (Ancillary Function Driver)    │
├─────────────────────────────────────────────────┤
│          tcpip.sys  (TCP/IP Stack)               │
│    ┌─────────────────────────────────────────┐  │
│    │         WFP Filter Engine               │  │  ← Most EDR filters live here
│    └─────────────────────────────────────────┘  │
├─────────────────────────────────────────────────┤
│          NDIS.sys  (Network Driver Interface)    │
│    ┌─────────────────────────────────────────┐  │
│    │      pacer.sys  (QoS Scheduler)         │  │  ← EDRChoker operates here
│    └─────────────────────────────────────────┘  │
├─────────────────────────────────────────────────┤
│          NIC Driver (miniport driver)            │
├─────────────────────────────────────────────────┤
│          Physical NIC hardware                   │
└─────────────────────────────────────────────────┘
```

Key insight: `pacer.sys` sits **below** WFP. Traffic throttled at the pacer level
bypasses WFP audit logging entirely.

---

## WFP Core Components

### 1. Filter Engine (Base Filtering Engine — BFE)
- The central service: `bfe.dll` / `bfe.sys`
- Maintained by the `Base Filtering Engine` Windows service
- Stores all filters, sublayers, providers, and callout registrations
- Accessible from user-mode via `fwpuclnt.dll` (Fwpm* APIs)

### 2. Layers

A **layer** is a specific inspection point in the network stack where filters are
evaluated. Each layer corresponds to a network event (e.g., outbound connection attempt).

Key layers for EDR evasion:

| Layer GUID / Name | Description |
|---|---|
| `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` | Fires once per **outbound** TCP/UDP connection initiation |
| `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6` | Fires once per **inbound** connection acceptance |
| `FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4/V6` | Fires when a flow (connection) is established |
| `FWPM_LAYER_OUTBOUND_TRANSPORT_V4/V6` | Every outbound transport-layer packet |
| `FWPM_LAYER_INBOUND_TRANSPORT_V4/V6` | Every inbound transport-layer packet |
| `FWPM_LAYER_IPPACKET_OUTBOUND` | Raw outbound IP packets |
| `FWPM_LAYER_IPPACKET_INBOUND` | Raw inbound IP packets |

> **ALE_AUTH_CONNECT is the most important layer** for EDR telemetry blocking —
> it fires once per connection (not per packet), making it efficient.

### 3. Sublayers

Within a layer, filters are grouped into **sublayers**. Multiple sublayers can exist
per layer. Each sublayer has a unique GUID.

The Windows Firewall uses its own sublayer GUID: `FWPM_SUBLAYER_UNIVERSAL`.

### 4. Filters

A **filter** is a rule within a sublayer. Each filter has:

```c
FWPM_FILTER0 filter = {0};
filter.layerKey         = FWPM_LAYER_ALE_AUTH_CONNECT_V4;  // which layer
filter.subLayerKey      = mySubLayerGuid;                    // which sublayer
filter.weight.type      = FWP_UINT64;
filter.weight.uint64    = &weight;                           // priority (higher = first)
filter.action.type      = FWP_ACTION_BLOCK;                  // or PERMIT / CALLOUT
filter.numFilterConditions = numConditions;
filter.filterCondition  = conditions;                        // match criteria
filter.flags            = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT; // hard decision
```

#### Filter Actions:
- `FWP_ACTION_BLOCK` — Block the traffic
- `FWP_ACTION_PERMIT` — Allow the traffic
- `FWP_ACTION_CALLOUT_TERMINATING` — Invoke a callout; callout makes final decision
- `FWP_ACTION_CALLOUT_INSPECTION` — Invoke a callout; callout cannot block

#### Filter Conditions (examples):
- Match by **application path**: `FWPM_CONDITION_ALE_APP_ID`
- Match by **remote IP**: `FWPM_CONDITION_IP_REMOTE_ADDRESS`
- Match by **remote port**: `FWPM_CONDITION_IP_REMOTE_PORT`
- Match by **user SID**: `FWPM_CONDITION_ALE_USER_ID`
- Match by **process ID**: `FWPM_CONDITION_ALE_PROCESS_ID` (Windows 10+)

### 5. Filter Weight and Evaluation Order

Within a sublayer, filters are evaluated in **descending weight order**. The first filter
whose conditions match determines the action.

```
Higher weight → evaluated first
```

A `BLOCK` result from one sublayer can be overridden by a `PERMIT` in another sublayer
— unless `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT` is set, which makes the decision **hard**
(final, not overridable by other sublayers).

#### Weight values:

```c
// Maximum weight — no other filter can be evaluated first
UINT64 maxWeight = 0xFFFFFFFFFFFFFFFF;

// Typical EDR filter weight (older implementations)
UINT64 normalWeight = 0x0000000000000001;
```

Hardened EDRs use `maxWeight` + `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT` together —
this creates a filter that **cannot be overridden by any other user-mode filter**.

### 6. Callouts

A **callout** is a kernel-mode driver function registered with WFP. Unlike simple
block/permit filters, callouts can:

- Inspect packet data (not just headers)
- Modify packets in-flight
- Make decisions based on deep packet content
- Issue verdicts that cannot be overridden (terminating callouts)

```c
// Registering a callout in kernel mode (simplified)
FWPS_CALLOUT callout = {0};
callout.calloutKey = myCalloutGuid;
callout.classifyFn = MyClassifyFunction;   // called for each matching packet
callout.notifyFn   = MyNotifyFunction;     // called when filter is added/removed
callout.flowDeleteFn = MyFlowDeleteFn;     // called when a flow ends
FwpsCalloutRegister(deviceObject, &callout, &calloutId);
```

Terminating callouts can set `classifyOut->actionType = FWP_ACTION_BLOCK` with
`classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE` — making the decision irrevocable.

---

## How EDRs Use WFP

### Telemetry Protection
EDRs add PERMIT filters for their own processes/IPs so their telemetry traffic is
never blocked even during a network containment incident.

### Network Containment
During incident response, EDRs add high-weight BLOCK filters that prevent all
network traffic from a compromised machine (except to the EDR's C2).

### Detection
Some EDRs register WFP callouts that inspect all outbound traffic from suspicious
processes, enabling network-level behavioral detection.

---

## Key Windows Event IDs for WFP Changes

| Event ID | Description |
|---|---|
| 5446 | WFP callout changed |
| 5447 | WFP filter added/deleted/changed |
| 5448 | WFP provider changed |
| 5449 | WFP provider context changed |
| 5450 | WFP sublayer changed |

These events are logged under **Security** event log (requires audit policy enabled).

---

## WFP Management APIs (User-mode)

```c
// Open session to BFE
FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engineHandle);

// Enumerate all filters
FwpmFilterEnum0(engineHandle, enumHandle, 100, &filters, &numFilters);

// Add a new filter
FwpmFilterAdd0(engineHandle, &filter, NULL, &filterId);

// Delete a filter by GUID key
FwpmFilterDeleteByKey0(engineHandle, &filterKey);

// Delete a filter by numeric ID
FwpmFilterDeleteById0(engineHandle, filterId);
```

All `Fwpm*` APIs are in `fwpuclnt.dll`, headers in `fwpmu.h`.

---

## Summary

WFP is the primary choke point for network-level EDR telemetry. Understanding its
layer/sublayer/filter/callout hierarchy is essential before studying any of the
offensive techniques in this module.

Next: `02_wfp-filter-injection.md`

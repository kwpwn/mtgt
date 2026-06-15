/*
 * tokens.c — Process Token Privilege Enumerator
 *
 * Enumerates all accessible processes, inspects their access tokens, and
 * scores them based on the presence of dangerous privileges.  High-scoring
 * processes are reported as interesting LPE targets or escalation starting
 * points.
 *
 * Scoring (same weight scheme as Ferrum Go edition):
 *   SeTcbPrivilege                     45
 *   SeCreateTokenPrivilege             45
 *   SeDebugPrivilege                   40
 *   SeImpersonatePrivilege             35
 *   SeAssignPrimaryTokenPrivilege      35
 *   SeBackupPrivilege                  30
 *   SeRestorePrivilege                 30
 *   SeLoadDriverPrivilege              25
 *   SeTakeOwnershipPrivilege           20
 *   SeManageVolumePrivilege            15
 *   + 20 if token is elevated
 *   + 15 if integrity >= HIGH or SYSTEM
 *
 * Processes with score > 30 are printed.
 */

#include "../common.h"

/* -----------------------------------------------------------------------
 * Privilege name → score table
 * --------------------------------------------------------------------- */
typedef struct { const wchar_t *name; int score; } PrivScore;

static const PrivScore g_privScores[] = {
    { L"SeTcbPrivilege",                    45 },
    { L"SeCreateTokenPrivilege",            45 },
    { L"SeDebugPrivilege",                  40 },
    { L"SeImpersonatePrivilege",            35 },
    { L"SeAssignPrimaryTokenPrivilege",     35 },
    { L"SeBackupPrivilege",                 30 },
    { L"SeRestorePrivilege",                30 },
    { L"SeLoadDriverPrivilege",             25 },
    { L"SeTakeOwnershipPrivilege",          20 },
    { L"SeManageVolumePrivilege",           15 },
    { NULL, 0 }
};

#define REPORT_THRESHOLD 30

/* -----------------------------------------------------------------------
 * Internal: inspect one process, return score (0 = skip / inaccessible).
 * Fills in username, integrityRID, elevated flag, and a list of matching
 * privilege names.
 * --------------------------------------------------------------------- */
typedef struct {
    wchar_t     username[256];
    DWORD       integrityRID;
    BOOL        elevated;
    wchar_t     matchedPrivs[1024];   /* comma-sep list */
    int         score;
} ProcInfo;

static BOOL InspectProcess(DWORD pid, ProcInfo *out) {
    memset(out, 0, sizeof(*out));

    HANDLE hProc = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return FALSE;

    HANDLE hTok = NULL;
    if (!OpenProcessToken(hProc, TOKEN_QUERY, &hTok)) {
        CloseHandle(hProc);
        return FALSE;
    }

    /* -- Username -- */
    DWORD needed = 0;
    GetTokenInformation(hTok, TokenUser, NULL, 0, &needed);
    TOKEN_USER *pTU = (TOKEN_USER *)HeapAlloc(GetProcessHeap(), 0, needed);
    if (pTU && GetTokenInformation(hTok, TokenUser, pTU, needed, &needed)) {
        wchar_t name[128] = {0}, dom[128] = {0};
        DWORD nCch = _countof(name), dCch = _countof(dom);
        SID_NAME_USE use;
        if (LookupAccountSidW(NULL, pTU->User.Sid, name, &nCch, dom, &dCch, &use))
            _snwprintf(out->username, _countof(out->username), L"%s\\%s", dom, name);
    }
    if (pTU) HeapFree(GetProcessHeap(), 0, pTU);

    /* -- Integrity level -- */
    out->integrityRID = GetProcessIntegrityRID(hProc);

    /* -- Elevation -- */
    out->elevated = IsProcessElevated(hProc);

    /* -- Privilege list -- */
    needed = 0;
    GetTokenInformation(hTok, TokenPrivileges, NULL, 0, &needed);
    TOKEN_PRIVILEGES *pTP =
        (TOKEN_PRIVILEGES *)HeapAlloc(GetProcessHeap(), 0, needed);
    if (pTP && GetTokenInformation(hTok, TokenPrivileges, pTP, needed, &needed)) {
        for (DWORD i = 0; i < pTP->PrivilegeCount; i++) {
            wchar_t privName[64] = {0};
            DWORD   privCch      = _countof(privName);
            if (!LookupPrivilegeNameW(NULL, &pTP->Privileges[i].Luid,
                                      privName, &privCch))
                continue;

            /* Both present+enabled and present-but-disabled are interesting */
            for (int k = 0; g_privScores[k].name; k++) {
                if (_wcsicmp(privName, g_privScores[k].name) == 0) {
                    out->score += g_privScores[k].score;
                    if (out->matchedPrivs[0])
                        wcsncat(out->matchedPrivs, L", ",
                                _countof(out->matchedPrivs) - wcslen(out->matchedPrivs) - 1);
                    wcsncat(out->matchedPrivs, privName,
                            _countof(out->matchedPrivs) - wcslen(out->matchedPrivs) - 1);
                }
            }
        }
    }
    if (pTP) HeapFree(GetProcessHeap(), 0, pTP);

    /* Bonus points */
    if (out->elevated)
        out->score += 20;
    if (out->integrityRID >= SECURITY_MANDATORY_HIGH_RID)
        out->score += 15;

    CloseHandle(hTok);
    CloseHandle(hProc);
    return TRUE;
}

/* -----------------------------------------------------------------------
 * Module entry
 * --------------------------------------------------------------------- */
void Module_Tokens(void) {
    PrintHeader(L"TOKEN PRIVILEGE AUDIT");

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        PrintInfo(L"  [!] Cannot snapshot processes (error %lu)\n", GetLastError());
        return;
    }

    PROCESSENTRY32W pe = { .dwSize = sizeof(pe) };
    DWORD findings = 0;
    BOOL  more     = Process32FirstW(hSnap, &pe);

    while (more) {
        ProcInfo info;
        if (InspectProcess(pe.th32ProcessID, &info) && info.score > REPORT_THRESHOLD) {

            /* Determine severity from score */
            Severity sev;
            if      (info.score >= 70) sev = SEV_CRITICAL;
            else if (info.score >= 50) sev = SEV_HIGH;
            else if (info.score >= 35) sev = SEV_MEDIUM;
            else                       sev = SEV_LOW;

            const wchar_t *intStr;
            if      (info.integrityRID >= SECURITY_MANDATORY_SYSTEM_RID)
                intStr = L"SYSTEM";
            else if (info.integrityRID >= SECURITY_MANDATORY_HIGH_RID)
                intStr = L"HIGH";
            else if (info.integrityRID >= SECURITY_MANDATORY_MEDIUM_RID)
                intStr = L"MEDIUM";
            else
                intStr = L"LOW";

            Finding f;
            f.severity = sev;
            wcscpy(f.module, L"TOKENS");
            _snwprintf(f.target, _countof(f.target),
                L"PID:%lu  %s  [%s]%s",
                pe.th32ProcessID, pe.szExeFile, intStr,
                info.elevated ? L" ELEVATED" : L"");
            _snwprintf(f.reason, _countof(f.reason),
                L"Score:%d  User:%s  Privs: %s",
                info.score, info.username, info.matchedPrivs);
            PrintFinding(&f);
            findings++;
        }
        more = Process32NextW(hSnap, &pe);
    }

    CloseHandle(hSnap);

    if (findings == 0)
        PrintInfo(L"  No processes with dangerous privilege combinations found.\n");
    else
        PrintInfo(L"  %lu process(es) exceed score threshold (%d).\n",
                  findings, REPORT_THRESHOLD);

    /* Convenience: also check OUR OWN token */
    PrintInfo(L"\n  [Current Process Token]\n");
    HANDLE hSelf = GetCurrentProcess();
    HANDLE hTok  = NULL;
    OpenProcessToken(hSelf, TOKEN_QUERY, &hTok);
    if (hTok) {
        DWORD needed = 0;
        GetTokenInformation(hTok, TokenPrivileges, NULL, 0, &needed);
        TOKEN_PRIVILEGES *pTP =
            (TOKEN_PRIVILEGES *)HeapAlloc(GetProcessHeap(), 0, needed);
        if (pTP && GetTokenInformation(hTok, TokenPrivileges, pTP, needed, &needed)) {
            for (DWORD i = 0; i < pTP->PrivilegeCount; i++) {
                wchar_t nm[64] = {0};
                DWORD   nmCch  = _countof(nm);
                LookupPrivilegeNameW(NULL, &pTP->Privileges[i].Luid, nm, &nmCch);
                BOOL enabled = (pTP->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0;

                /* Colour dangerous privs */
                for (int k = 0; g_privScores[k].name; k++) {
                    if (_wcsicmp(nm, g_privScores[k].name) == 0) {
                        if (!g_noColor)
                            wprintf(L"    " CLR_YELLOW L"[DANGEROUS]" CLR_RESET
                                    L" %-40s %s\n",
                                    nm, enabled ? L"[Enabled]" : L"[Disabled]");
                        else
                            wprintf(L"    [DANGEROUS] %-40s %s\n",
                                    nm, enabled ? L"[Enabled]" : L"[Disabled]");
                        goto next_priv;
                    }
                }
                wprintf(L"             %-40s %s\n",
                        nm, enabled ? L"[Enabled]" : L"[Disabled]");
next_priv:;
            }
        }
        if (pTP) HeapFree(GetProcessHeap(), 0, pTP);
        CloseHandle(hTok);
    }
}

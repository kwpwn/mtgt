# sv_service.exe — Complete Reverse Engineering Reference

## Binary Info

| Field | Value |
|---|---|
| File | sv_service.exe |
| Arch | x86 (32-bit PE) — WoW64 trên Windows 64-bit |
| Service name | TopsecVpnSvc |
| Service user | **SYSTEM** |
| Product | Topsec / NGVONE SSL VPN Client |
| Default install | `C:\Program Files (x86)\NGVONE\Client\` |
| Entry point | `start` → `__tmainCRTStartup` → `wmain` @ **0x462900** |
| Service main | `sub_4653D0` @ **0x4653D0** |
| UDP listener thread | `StartAddress` @ **0x462EB0** |
| Embedded crypto | OpenSSL (statically linked) |

---

## Protocol

| Field | Value |
|---|---|
| Transport | UDP |
| Bind address | `127.0.0.1:4499` (0x1193) |
| Packet size | **4096 bytes cố định** |
| Authentication | **KHÔNG CÓ** |
| Dispatcher | `buf[0]` = command byte |
| Threading | Single-threaded `recvfrom` loop |

### Tại sao lại là localhost UDP không có auth?

Service này được thiết kế như một **local IPC daemon** — chỉ nhận lệnh từ VPN client GUI (`na_client.exe`) chạy cùng máy. Developer assume rằng chỉ tiến trình đáng tin cậy trên máy mới gửi packet đến 127.0.0.1:4499, nên không cài thêm cơ chế xác thực.

**Tại sao UDP thay vì pipe hoặc socket?** UDP đơn giản hơn để implement giao tiếp một chiều (fire-and-forget). Nhiều lệnh không cần response, UDP phù hợp. Nhược điểm: không có state, không track kết nối, và bất kỳ process nào trên máy đều gửi được.

**Tại sao 4096 bytes cố định?** `recvfrom(buf, 4096)` — service dùng buffer static trên stack, không cần biết trước kích thước thực tế. Tất cả field đều là offset tuyệt đối trong buffer này.

**Attack surface:** Bất kỳ process nào chạy với quyền bất kỳ (kể cả user thường) đều có thể gửi lệnh cho SYSTEM service qua UDP 127.0.0.1:4499. Đây là local privilege escalation.

### Packet layout

```
Offset     Size   Field
------     ----   -----
[0]          1    Command byte — dispatcher key
[1]          1    Sub-param (log level cho cmd 0x17)
[4..283]   280    String / path argument (MBCS, null-terminated)
[264]        1    Session ID (cmd 0x01/0x02/0x03) — nằm TRONG vùng path
[284..287]   4    DWORD: data length
[288..291]   4    DWORD: trigger flag (cmd 0x05) / init() arg (cmd 0x04)
[296+]       -    DNS entries payload (cmd 0x05)
[548]        1    Sub-flag (cmd 0x04)
[552+]       -    Extra base64 arg (cmd 0x04)
```

**Tại sao [264] nằm trong vùng path [4..283]?** Vùng path là 280 bytes, offset 264 tính từ đầu buffer = offset 260 tính từ [4]. Khi path exe ngắn hơn 260 bytes thì byte [264] bằng 0 (null terminator padding). Service đọc byte này như một field riêng biệt qua `(unsigned char)buf[264]` — đây là cách layout implicit, không có padding field tường minh.

---

## Hàm quan trọng

| Địa chỉ | Tên gốc | Chức năng thực |
|---|---|---|
| **0x462EB0** | `StartAddress` | UDP recvfrom loop — dispatcher chính |
| **0x462490** | `sub_462490` | Authenticode check trước khi spawn process |
| **0x462330** | `sub_462330` | RSA verify (có 2 bug nghiêm trọng) |
| **0x4023A0** | `sub_4023A0` | Tail-call wrapper gọi `rsa->meth->rsa_pub_dec` |
| **0x4616B0** | `sub_4616B0` | Spawn process với token của Explorer |
| **0x4625C0** | `sub_4625C0` | Spawn process với token của SYSTEM service |
| **0x465DE0** | `sub_465DE0` | IsWow64Process — detect 32/64-bit Windows |
| **0x462D80** | `sub_462D80` | Đọc/ghi `SrvRunFlag` trong registry |
| **0x460670** | `sub_460670` | Lấy install directory từ registry |
| **0x460730** | `sub_460730` | Load `sv_shm.dll`, gọi `SHMEM_SetRunTimeSHMMStatus` |
| **0x461010** | `sub_461010` | Kill process theo tên (luôn return 0) |
| **0x4610D0** | `sub_4610D0` | Lấy PID của explorer.exe |
| **0x465BF0** | `sub_465BF0` | Base64 encode |
| **0x465D40** | `sub_465D40` | Base64 decode |
| **0x45E4E0** | `sub_45E4E0` | Đọc mainboard serial number qua WMI |
| **0x465E30** | `sub_465E30` | Thread reset VPN NIC |

---

## sub_462490 — Authenticode Check

**Địa chỉ:** `0x462490`
**Gọi bởi:** `sub_4616B0` @ 0x4616DB, `sub_4625C0` @ 0x4625E8, `sub_461D40` @ 0x461D6B

**Mục đích thiết kế:** Đảm bảo exe được spawn là phần mềm do Topsec phát hành (ký bởi DigiCert CA mà Topsec dùng), ngăn attacker lạm dụng service để chạy exe tùy ý.

### Code đầy đủ

```c
int sub_462490(wchar_t *pvObject)  // pvObject = exe path
{
    int v1 = 0;  // mặc định = BLOCKED

    // ── Gate 1: Windows XP / Server 2003 ──────────────────────────────
    // GetVersion() trả DWORD: low byte = major version
    // Windows XP = 5, Vista = 6, 7/8/10/11 = 6+
    if ((unsigned char)GetVersion() < 6) {
        log("win7");
        return 1;  // BYPASS hoàn toàn trên XP
    }

    // ── Gate 2: Kiểm tra 32-bit hay 64-bit OS ─────────────────────────
    HMODULE k32 = GetModuleHandleW(L"kernel32");
    void *IsWow64Process = GetProcAddress(k32, "IsWow64Process");
    BOOL v13 = 0;
    if (IsWow64Process)
        IsWow64Process(GetCurrentProcess(), &v13);

    if (!v13) {
        log("32");
        return 1;  // BYPASS trên native 32-bit Windows
    }

    // ── Gate 3: Phải có Authenticode signature ─────────────────────────
    DWORD enc, content, fmt;
    HCERTSTORE phCertStore = NULL;
    HCRYPTMSG  phMsg       = NULL;
    DWORD pcbData = 0;

    if (!CryptQueryObject(
            CERT_QUERY_OBJECT_FILE, pvObject,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, 2,
            0, &enc, &content, &fmt, &phCertStore, &phMsg, NULL))
        goto cleanup;  // không có sig → v1 = 0 → BLOCKED

    // ── Gate 4: Đọc CMSG_SIGNER_INFO ──────────────────────────────────
    if (!CryptMsgGetParam(phMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &pcbData))
        goto cleanup;

    BYTE *v6 = LocalAlloc(LMEM_ZEROINIT, pcbData);
    if (!CryptMsgGetParam(phMsg, CMSG_SIGNER_INFO_PARAM, 0, v6, &pcbData))
        goto cleanup;

    // ── Gate 5: Gọi sub_462330 để verify chữ ký ───────────────────────
    // v6 trỏ vào CMSG_SIGNER_INFO struct:
    //   offset 44 (index 11 của DWORD array) = EncryptedHash.cbData
    //   offset 48 (index 12 của DWORD array) = EncryptedHash.pbData
    if (!sub_462330(v6[12], v6[11]))  // truyền pbData, cbData
        v1 = 1;  // sub_462330 trả 0 → PASS

cleanup:
    CertCloseStore(phCertStore, 0);
    CryptMsgClose(phMsg);
    LocalFree(v6);
    return v1;
}
```

### Tại sao Gate 1: GetVersion() < 6 bypass hoàn toàn?

`GetVersion()` trả major version của Windows trong low byte:
- Windows XP/2003 = **5** → < 6 → bypass
- Windows Vista = **6** → không bypass
- Windows 7/8/10/11 = **6** hoặc **10** → không bypass

Developer giả định rằng trên Windows XP không có `CryptQueryObject` đủ mạnh hoặc Authenticode không được enforce. Thực tế `CryptQueryObject` có trên XP nhưng developer muốn backward-compatible với môi trường cũ. Kết quả: mọi Windows XP đều bypass check hoàn toàn.

### Tại sao Gate 2: IsWow64Process bypass 32-bit Windows?

`IsWow64Process(GetCurrentProcess(), &v13)` kiểm tra xem process _hiện tại_ (sv_service.exe) có đang chạy trong WoW64 layer hay không:
- **64-bit Windows**: sv_service.exe là 32-bit PE chạy qua WoW64 → `v13 = TRUE`
- **32-bit Windows**: không có WoW64 → hàm không tồn tại hoặc trả FALSE → `v13 = FALSE`

Khi `v13 = FALSE` (32-bit Windows), return 1 ngay — bypass hoàn toàn. Developer có lẽ muốn tránh dependency vào Authenticode API trên môi trường 32-bit cũ, hoặc đây là code path legacy cho Windows XP 32-bit không thực sự cần verify.

**Hệ quả:** Service chạy trên máy Windows 32-bit cũ là hoàn toàn không có protection.

### Tại sao CMSG_SIGNER_INFO[11] và [12] là EncryptedHash?

`CMSG_SIGNER_INFO` là struct của WinCrypt chứa thông tin về người ký trong một PKCS#7 message. Khi developer truy cập `v6[11]` và `v6[12]` (coi v6 là DWORD array), đây là các field:

```c
// CMSG_SIGNER_INFO layout (offset tính bằng bytes):
// Offset  0:  DWORD  dwVersion
// Offset  4:  CERT_NAME_BLOB  Issuer        (2 DWORD = cbData + pbData)
// Offset 12:  CRYPT_INTEGER_BLOB  SerialNumber (2 DWORD)
// Offset 20:  CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm (nhiều field)
// Offset 28:  CRYPT_ALGORITHM_IDENTIFIER  HashEncryptionAlgorithm
// Offset 36:  CRYPT_DATA_BLOB  EncryptedHash   ← ĐÂY
//               +0 = cbData (số bytes của hash đã encrypt)  → v6[9]? 
// ...

// Thực tế IDA decompile cho v6[11] = offset 44 = EncryptedHash.cbData
//                              v6[12] = offset 48 = EncryptedHash.pbData
```

`EncryptedHash` trong Authenticode là **chữ ký RSA của file** — hash của PE file được mã hóa (sign) bằng private key của người ký. Kích thước của nó = kích thước RSA key / 8 bytes (ví dụ: RSA2048 → 256 bytes, RSA4096 → 512 bytes).

**Vấn đề:** Developer lấy `EncryptedHash` của **file đang verify** và đem đi decrypt bằng public key của **DigiCert CA**. Đây là sai logic hoàn toàn (xem Bug 1 trong sub_462330).

### Flow chart

```
GetVersion() < 6  ──────────────────────────────────► BYPASS (return 1)
    │ NO (Vista+)
    ▼
IsWow64Process == FALSE (32-bit Windows)  ───────────► BYPASS (return 1)
    │ NO (64-bit Windows)
    ▼
CryptQueryObject FAIL (không có Authenticode)  ──────► BLOCKED (return 0)
    │ OK
    ▼
CryptMsgGetParam → CMSG_SIGNER_INFO
    ▼
sub_462330(EncryptedHash.pbData, EncryptedHash.cbData)
    ├─ returns 0  ──────────────────────────────────► PASS (return 1)
    └─ returns 1  ──────────────────────────────────► BLOCKED (return 0)
```

---

## sub_462330 — RSA Verify (BUG ANALYSIS)

**Địa chỉ:** `0x462330`
**Gọi bởi:** `sub_462490` @ 0x462583

### Mục đích thiết kế

Developer muốn xác minh rằng exe được ký bởi DigiCert CA mà Topsec sử dụng:

```
Topsec private key  ──sign──►  exe's Authenticode signature
DigiCert CA private key  ──sign──►  Topsec's cert signature
```

Logic đúng là: lấy **signature của Topsec cert** (trong chain), decrypt bằng **DigiCert CA public key**, so sánh với hash của cert. Nếu khớp → cert là do DigiCert CA cấp.

### Pseudocode thực tế

```c
int sub_462330(BYTE *pbData,   // EncryptedHash.pbData (từ FILE's PKCS7)
               DWORD cbData)   // EncryptedHash.cbData
{
    char  pem[2416];
    BYTE  outbuf[1028];

    // ── Bước 1: hardcode DigiCert CA cert PEM vào stack ───────────────
    // "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
    // Đây là intermediate CA cert mà Topsec mua certificate từ đó
    strcpy(pem,
        "-----BEGIN CERTIFICATE-----\r\n"
        "MIIGsDCCBJigAwIBAgIQCK1AsmDSnEyfXs2pvZOu2TANBgkqhkiG9w0BAQwFADBi\r\n"
        // ... (2400+ bytes PEM data)
        "-----END CERTIFICATE-----");

    // ── Bước 2: Parse PEM → X509 struct ───────────────────────────────
    BIO  *bio  = BIO_new_mem_buf(pem, strlen(pem));  // OpenSSL BIO
    X509 *x509 = PEM_read_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!x509) return 1;  // parse fail → BLOCKED

    // ── Bước 3: Lấy RSA public key từ cert DigiCert CA ────────────────
    // DigiCert G4 Code Signing CA là RSA4096 → RSA_size(rsa) = 512 bytes
    EVP_PKEY *pkey = X509_get_pubkey(x509);      // sub_401F50
    RSA      *rsa  = EVP_PKEY_get1_RSA(pkey);   // RSA_size(rsa) = 512

    // ── Bước 4: Gọi RSA_public_decrypt ────────────────────────────────
    // assembly @ 0x462448:
    //   push 3              ← RSA_NO_PADDING (BUG!)
    //   push eax            ← rsa
    //   lea  eax, [ebp+var_408]
    //   push eax            ← outbuf
    //   push [ebp+var_D7C]  ← pbData (EncryptedHash bytes của FILE)
    //   push ebx            ← cbData
    //   call sub_4023A0
    //   add  esp, 14h       ← 5 args × 4 = 20 bytes, confirm 5 args
    int result = sub_4023A0(cbData, pbData, outbuf, rsa, /*padding=*/3);

    EVP_PKEY_free(pkey);

    if (result == -1) return 1;  // decrypt fail → BLOCKED
    return 0;                    // PASS
}
```

### Tại sao cert DigiCert hardcode vào stack?

Developer nhúng trực tiếp PEM string vào code thay vì đọc từ Windows Certificate Store. Lý do có thể:
1. Không muốn phụ thuộc vào cert store của OS (có thể bị user xóa/sửa)
2. Muốn "pin" đúng CA này, tránh trust CA khác trong store
3. Code được viết offline và nhúng vào lúc build

**Hệ quả:** Khi DigiCert G4 CA hết hạn hoặc bị revoke, toàn bộ check bị broken và phải recompile service.

### sub_4023A0 @ 0x4023A0 — Tại sao IDA thấy 4 args nhưng thực tế là 5?

```asm
sub_4023A0:
  mov  eax, [esp+10h]     ; a4 = RSA*
  mov  ecx, [eax+8]       ; rsa->meth = RSA_METHOD* tại offset 8 của RSA struct
  mov  [esp+10h], eax     ; ghi lại (redundant)
  mov  ecx, [ecx+8]       ; meth->rsa_pub_dec tại offset 8 của RSA_METHOD
  jmp  ecx                ; TAIL CALL — không push thêm gì, không tạo frame mới
```

IDA decompiler thấy hàm này không có `ret` và kết thúc bằng `jmp ecx` nên hiểu nhầm là call hàm khác với 0 args. Thực tế `jmp ecx` là **tail call optimization**: thay vì `call + ret`, dùng `jmp` để nhảy thẳng vào `rsa_pub_dec`, và `rsa_pub_dec` sẽ `ret` trực tiếp về caller của `sub_4023A0`.

**Cơ chế:** Vì `jmp` không tạo stack frame mới, `rsa_pub_dec` thấy **toàn bộ stack frame của caller** (sub_462330), bao gồm cả argument thứ 5 (`padding = 3`) mà sub_4023A0 không biết đến:

```
Khi sub_462330 gọi sub_4023A0:
[esp]    = return address (vào sub_462330)
[esp+4]  = a1 = cbData   → rsa_pub_dec: flen
[esp+8]  = a2 = pbData   → rsa_pub_dec: from
[esp+C]  = a3 = &outbuf  → rsa_pub_dec: to
[esp+10] = a4 = RSA*     → rsa_pub_dec: rsa
[esp+14] = a5 = 3        → rsa_pub_dec: padding  ← IDA KHÔNG THẤY CÁI NÀY

Sau jmp ecx, rsa_pub_dec đọc [esp+14] = 3 = RSA_NO_PADDING ← BUG
```

IDA chỉ thấy `add esp, 14h` (5 × 4 = 20) ở call site, xác nhận có đúng 5 args.

### Hai bug xếp chồng

**Bug 1 — Sai data input (logic error):**

Developer lấy `EncryptedHash` của **file đang verify** (là signature RSA của file, ký bởi Topsec private key) rồi decrypt bằng public key của **DigiCert CA**. Hai key này hoàn toàn không liên quan:

```
Đúng ra phải làm:
  digest = SHA384(TbsCertificate của Topsec cert)
  signature = cert.SignatureValue (bytes ký bởi DigiCert CA)
  verify: RSA_verify(digest, signature, DigiCert_CA_pubkey)

Thực tế code làm:
  input = EncryptedHash của FILE (ký bởi Topsec private key)
  result = RSA_public_decrypt(input, DigiCert_CA_pubkey, RSA_NO_PADDING)
  → decrypt một thứ bằng key không phải của nó → output vô nghĩa
  → NHƯNG với RSA_NO_PADDING, output vô nghĩa vẫn PASS
```

**Bug 2 — RSA_NO_PADDING (critical):**

```c
// OpenSSL RSA_NO_PADDING constants:
#define RSA_PKCS1_PADDING   1   // verify PKCS1 v1.5 padding → thực sự check
#define RSA_NO_PADDING      3   // không check gì cả → luôn thành công

// Trong OpenSSL rsa_ossl_public_decrypt():
int rsa_ossl_public_decrypt(int flen, const unsigned char *from,
                             unsigned char *to, RSA *rsa, int padding)
{
    // ... RSA raw operation: to = from^e mod n ...
    int i = RSA_size(rsa);  // = 512 cho RSA4096
    // ...
    int r;
    switch (padding) {
    case RSA_PKCS1_PADDING:
        r = RSA_padding_check_PKCS1_type_1(to, i, buf, i, i);
        // ^ thực sự verify: check byte 0x00 0x01 0xFF...FF 0x00 <digest>
        // → trả -1 nếu padding sai (tức là wrong key)
        break;
    case RSA_NO_PADDING:
        r = RSA_padding_check_none(to, i, buf, i, i);
        // ^ CHỈ copy bytes, không check gì cả
        // → LUÔN trả i (= 512), KHÔNG BAO GIỜ trả -1
        break;
    }
    return r;  // -1 = fail, >0 = success
}
```

Vì `rsa_pub_dec` nhận `padding = 3 = RSA_NO_PADDING`, nó sẽ:
1. Thực hiện RSA raw operation: `output = input^e mod n` (math đơn thuần)
2. Gọi `RSA_padding_check_none()` → copy bytes, return 512
3. Không bao giờ return -1

**Kết quả:** sub_4023A0 luôn trả 512 (≠ -1), sub_462330 luôn trả 0, sub_462490 luôn trả 1 (PASS) — với điều kiện `cbData ≤ RSA_size(rsa_ca) = 512`.

### Điều kiện PASS trên 64-bit Windows

```
EncryptedHash.cbData ≤ 512  AND  file có Authenticode PKCS7 structure hợp lệ
```

| Loại chữ ký | EncryptedHash size | Kết quả |
|---|---|---|
| Không có sig | N/A | **BLOCKED** — CryptQueryObject fail |
| Self-signed RSA1024 | 128 bytes ≤ 512 | **PASS** ✓ |
| Self-signed RSA2048 | 256 bytes ≤ 512 | **PASS** ✓ |
| Microsoft RSA2048 | 256 bytes ≤ 512 | **PASS** ✓ |
| DigiCert RSA4096 (Topsec) | 512 bytes ≤ 512 | **PASS** ✓ |
| RSA8192 (hiếm) | 1024 bytes > 512 | BLOCKED — cbData > RSA_size |

**Bypass:** Ký bất kỳ exe nào bằng RSA2048 self-signed cert. Không cần CA trust, không cần timestamp, không cần expiry hợp lệ. Chỉ cần PKCS7 structure đúng format.

---

## sub_465DE0 — IsWow64Process (bị IDA đặt tên sai)

**Địa chỉ:** `0x465DE0`

```c
BOOL sub_465DE0(void) {
    HMODULE k32 = GetModuleHandleW(L"kernel32");
    BOOL (WINAPI *fn_IsWow64Process)(HANDLE, PBOOL) =
        (BOOL(WINAPI*)(HANDLE,PBOOL)) GetProcAddress(k32, "IsWow64Process");

    BOOL v3 = 0;
    if (fn_IsWow64Process)
        fn_IsWow64Process(GetCurrentProcess(), &v3);

    return v3;
}
```

### Tại sao GetProcAddress thay vì import trực tiếp?

`IsWow64Process` chỉ có từ Windows XP SP2. Nếu import trực tiếp trong IAT, service sẽ fail to load trên Windows XP RTM/SP1. `GetProcAddress` là cách safe load: nếu hàm không tồn tại, trả NULL và `v3` giữ = 0 (FALSE = 32-bit behavior).

### WoW64 là gì?

**WoW64** (Windows on Windows 64) là subsystem cho phép process 32-bit chạy trên Windows 64-bit. sv_service.exe là 32-bit PE, nên khi chạy trên Windows 10/11 64-bit, nó chạy trong WoW64. `IsWow64Process(self)` sẽ trả TRUE.

```
Windows 64-bit:
  sv_service.exe (32-bit)  →  WoW64 layer  →  NT kernel (64-bit)
  IsWow64Process(self) = TRUE

Windows 32-bit:
  sv_service.exe (32-bit)  →  NT kernel (32-bit)
  IsWow64Process không tồn tại hoặc trả FALSE
```

### Tại sao dùng cái này để phân nhánh logic?

```c
// Trong cmd 0x01 / 0x03 dispatcher:
if (sub_465DE0() == 1) {          // 64-bit Windows
    sub_4625C0(buf[264], path);   // SYSTEM token
} else {                           // 32-bit Windows
    sub_4616B0(buf[264], na_client_path);  // Explorer token, path cố định
}
```

Trên 32-bit Windows cũ, developer dùng path an toàn hơn (Explorer token, path cố định), tránh phức tạp. Trên 64-bit Windows hiện đại, dùng SYSTEM token vì đây là môi trường production chính thức. Đây là conditional logic theo OS generation, không liên quan gì đến session.

---

## sub_4616B0 — Spawn Process với Explorer Token

**Địa chỉ:** `0x4616B0`
**Dùng bởi:** cmd `0x01` (fallback 32-bit), cmd `0x02`

```c
void sub_4616B0(BYTE sessionId, wchar_t *exePath)
{
    // ── Bước 1: Lấy PID của explorer.exe ──────────────────────────────
    DWORD explorerPid = sub_4610D0();  // @ 0x4610D0
    // sub_4610D0: CreateToolhelp32Snapshot → tìm "explorer.exe" → return PID

    // ── Bước 2: Mở explorer process và lấy token ──────────────────────
    HANDLE hExplorer = OpenProcess(PROCESS_ALL_ACCESS, FALSE, explorerPid);
    HANDLE hToken;
    OpenProcessToken(hExplorer, TOKEN_ALL_ACCESS, &hToken);

    // ── Bước 3: Setup ACL cho token (allow Everyone) ──────────────────
    // BuildExplicitAccessWithNameW("Everyone", GENERIC_ALL, GRANT_ACCESS, ...)
    // SetEntriesInAcl → SetKernelObjectSecurity
    // Cho phép service (SYSTEM) manipulate token của user process

    // ── Bước 4: Duplicate token → Primary token ───────────────────────
    HANDLE phNewToken;
    DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation,
                     TokenPrimary, &phNewToken);
    // DuplicateTokenEx cần vì CreateProcessAsUserW yêu cầu Primary token
    // Token gốc từ OpenProcessToken có thể là Impersonation token

    // ── Bước 5: Gán session ID ────────────────────────────────────────
    DWORD sid = sessionId;
    SetTokenInformation(phNewToken, TokenSessionId, &sid, sizeof(DWORD));
    // Đây là lý do buf[264] quan trọng — xem section Session 0 Isolation

    // ── Bước 6: Tạo environment block và spawn ────────────────────────
    void *Environment;
    CreateEnvironmentBlock(&Environment, phNewToken, FALSE);

    STARTUPINFOW si = {0};
    si.cb        = sizeof(si);
    si.lpDesktop = L"WinSta0\\Default";  // hardcode — phải match session ID

    PROCESS_INFORMATION pi;
    CreateProcessAsUserW(phNewToken, exePath, NULL, NULL, NULL,
                         FALSE, CREATE_UNICODE_ENVIRONMENT,
                         Environment, NULL, &si, &pi);
}
```

### Tại sao phải OpenProcessToken(explorer) thay vì tự tạo token?

Để spawn process với **identity của user đang login**, service phải lấy token của user đó. Token này chứa: SID của user, group memberships, privileges của user. Cách đơn giản nhất là lấy token từ một process đang chạy với identity đó — explorer.exe là perfect vì luôn chạy với user identity trên interactive session.

**Tại sao cần DuplicateTokenEx?** `OpenProcessToken` trả handle nhưng không cho phép dùng trực tiếp với `CreateProcessAsUserW` vì đó là **Impersonation token**. `CreateProcessAsUserW` yêu cầu **Primary token**. `DuplicateTokenEx(..., TokenPrimary, ...)` convert type.

### Tại sao cần setup ACL ("Everyone")?

sv_service.exe chạy as SYSTEM. explorer.exe chạy as User. Mặc định, SYSTEM không có quyền `PROCESS_ALL_ACCESS` trên process của User (mặc dù SYSTEM là admin). Phải thêm ACE "Everyone → GENERIC_ALL" vào DACL của token handle để bypass restriction này. Đây là step unusual và có thể bị EDR flag.

---

## sub_4625C0 — Spawn Process với SYSTEM Token

**Địa chỉ:** `0x4625C0`
**Dùng bởi:** cmd `0x01` (64-bit), cmd `0x03`

```c
void sub_4625C0(BYTE sessionId, wchar_t *exePath)
{
    // ── Bước 1: Lấy token của chính service (SYSTEM) ──────────────────
    HANDLE hSelf = GetCurrentProcess();  // sv_service.exe process handle
    HANDLE hToken;
    OpenProcessToken(hSelf, TOKEN_ALL_ACCESS, &hToken);
    // sv_service.exe chạy as SYSTEM → token này là SYSTEM token

    // ── Bước 2: Duplicate → Primary token ────────────────────────────
    HANDLE phNewToken;
    DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation,
                     TokenPrimary, &phNewToken);

    // ── Bước 3: QUAN TRỌNG — chuyển token sang session của user ───────
    DWORD sid = sessionId;
    SetTokenInformation(phNewToken, TokenSessionId, &sid, sizeof(DWORD));
    // Nếu sid = 0: token ở Session 0 → process exit ngay (Session 0 Isolation)
    // Nếu sid = 1: token ở Session 1 → process chạy trên desktop user
    // Yêu cầu SE_TCB_PRIVILEGE (chỉ SYSTEM có)

    // ── Bước 4: Spawn ─────────────────────────────────────────────────
    void *Environment;
    CreateEnvironmentBlock(&Environment, phNewToken, FALSE);

    STARTUPINFOW si = {0};
    si.cb        = sizeof(si);
    si.lpDesktop = L"WinSta0\\Default";

    PROCESS_INFORMATION pi;
    CreateProcessAsUserW(phNewToken, exePath, NULL, NULL, NULL,
                         FALSE, CREATE_UNICODE_ENVIRONMENT,
                         Environment, NULL, &si, &pi);
}
```

### Tại sao đây là SYSTEM RCE?

Process được spawn kế thừa token của SYSTEM (sv_service.exe), nhưng được đặt vào interactive session của user. Kết quả:
- Process chạy với **SYSTEM privileges** — `whoami` trả `NT AUTHORITY\SYSTEM`
- Process hiển thị trên **desktop của user** (nếu là GUI)
- Process có thể đọc/ghi **mọi file, registry, process** trên hệ thống

### Tại sao cần SE_TCB_PRIVILEGE?

`SetTokenInformation(token, TokenSessionId, ...)` để thay đổi session của token yêu cầu privilege **SeTcbPrivilege** ("Act as part of the operating system"). Đây là privilege đặc biệt chỉ được cấp cho SYSTEM và một số service đặc biệt của OS. User thường, kể cả local Administrator, không có privilege này. sv_service.exe chạy as SYSTEM nên có.

---

## Session 0 Isolation — Tại sao buf[264]=0 gây process exit ngay

### Lịch sử: Tại sao Microsoft tạo ra Session 0 Isolation?

Trước Windows Vista, tất cả services và user applications đều chạy trong **Session 0** chung. Điều này cho phép service tương tác với desktop của user (SystemParametersInfo, SendMessage, ...). Vào đầu 2000s, các nhà nghiên cứu bảo mật phát hiện "Shatter attacks": vì Windows message queue không có access control, user-mode code có thể gửi message đặc biệt đến SYSTEM service window và làm service thực thi code tùy ý — đây là local privilege escalation dễ dàng.

**Microsoft giải quyết bằng Session 0 Isolation (Vista+):**

```
Session 0 (Isolated — không có desktop tương tác)
┌──────────────────────────────────────────────────┐
│  svchost.exe, TopsecVpnSvc, LSA, SCM, Winlogon  │
│  Window station: Service-0x0-3e7$\Default        │
│  KHÔNG có WinSta0\Default                        │
│  KHÔNG có interactive desktop                    │
└──────────────────────────────────────────────────┘

Session 1 (Interactive — có desktop)
┌──────────────────────────────────────────────────┐
│  explorer.exe, cmd.exe, notepad.exe, ...         │
│  Window station: WinSta0                         │
│  Desktop: WinSta0\Default                        │
│  Session ID = 1 (thường)                         │
└──────────────────────────────────────────────────┘
```

### Tại sao process exit ngay khi buf[264] = 0?

```
sub_4625C0 / sub_4616B0:
  SetTokenInformation(token, TokenSessionId, &buf[264]=0)
  ↓ token được gán vào Session 0
  
  StartupInfo.lpDesktop = L"WinSta0\\Default"  ← hardcode, không thay đổi
  ↓
  CreateProcessAsUserW(token, exe, ..., lpDesktop="WinSta0\Default")
  ↓
  OS tạo process, resolve "WinSta0\Default" trong Session 0
  ↓
  Session 0 không có "WinSta0" window station → OpenWindowStation() FAIL
  ↓
  Process loader (ntdll) không thể attach desktop → LdrInitializeThunk fail
  ↓
  Process exit với code 0xC0000142 (STATUS_DLL_INIT_FAILED)
  hoặc exit 0 nếu không có GUI/console dependency
```

**Tại sao CreateProcessAsUserW vẫn SUCCESS?** Hàm này chỉ tạo process object và thread object trong kernel — nó không verify xem desktop có accessible không tại thời điểm tạo. Process init fail sau đó trong user-mode (ntdll.dll initialization), không phải trong kernel.

### SetTokenInformation(TokenSessionId) hoạt động thế nào?

```c
DWORD sessionId = buf[264];  // 0, 1, 2, ...
SetTokenInformation(
    phNewToken,
    TokenSessionId,    // = 12, thay đổi session của token
    &sessionId,
    sizeof(DWORD)
);
```

API này gọi `NtSetInformationToken(TokenSessionId)` trong kernel. Kernel update trường `SessionId` trong `_TOKEN` structure. Sau đó khi `CreateProcessAsUserW` tạo process với token này, process được đặt vào session tương ứng.

**Privilege:** `SeTcbPrivilege` bắt buộc. Chỉ SYSTEM có. User thường / Administrator không có → gọi sẽ fail với `ERROR_PRIVILEGE_NOT_HELD`.

### Fix: Session ID phải là session của user

```powershell
# Lấy session ID của interactive user
(Get-Process -Name explorer | Select-Object -First 1).SessionId
# Thường = 1 trên máy đơn người dùng Windows 10/11

# Hoặc:
query session
# Active session có (*), cột "ID" là session ID cần dùng
```

```python
# Trong exploit:
buf[264] = 1   # interactive user session
# Nếu fail: thử 2, 3 (RDP session, multi-user)
```

### Bảng tổng hợp

| buf[264] | OS | Cmd | Token | Kết quả |
|---|---|---|---|---|
| **0** | 64-bit | 0x01/0x03 | SYSTEM | Process exit ngay (Session 0) |
| **0** | 64-bit | 0x02 | Explorer | Process exit ngay (Session 0) |
| **1** | 64-bit | 0x01/0x03 | **SYSTEM** | Chạy trên desktop user — RCE |
| **1** | 64-bit | 0x02 | Explorer user | Chạy trên desktop user |
| **1** | 32-bit | 0x01/0x03 | Explorer | Chạy nhưng path = na_client.exe cố định |
| **1** | 32-bit | 0x02 | Explorer | Chạy với path từ buf[4] |

---

# Chi tiết từng Command

---

## CMD 0x01 / 0x02 / 0x03 — Launch Process

### Tại sao có 3 command gần giống nhau?

Topsec VPN client có nhiều loại thao tác launch process:
- **0x01**: "Start SV service component" — dùng SYSTEM token khi trên 64-bit (môi trường production)
- **0x02**: "Start client component" — luôn dùng Explorer token (chạy với identity user)
- **0x03**: "Start WinLogon component" — copy logic của 0x01, có thể là code path riêng trong IPC protocol

Trên 64-bit Windows, 0x01 và 0x03 đều gọi `sub_4625C0` — hoàn toàn giống nhau. Đây có thể là code copy-paste hoặc hai message type khác nhau trong giao thức nhưng merge implementation.

### CMD 0x01 — Handler @ 0x4649B4

```c
// Signature check trước tiên:
// sub_4616B0 @ 0x4616DB gọi sub_462490(exePath)
// sub_4625C0 @ 0x4625E8 gọi sub_462490(exePath)

// Dispatcher:
if (sub_465DE0() == 1) {       // IsWow64 = TRUE → 64-bit Windows
    sub_4625C0(buf[264], WideStr_from_buf4);
    // → SYSTEM token, custom path từ buf[4]
} else {                        // 32-bit Windows
    path = install_dir + L"na_client.exe";
    sub_4616B0(buf[264], path);
    // → Explorer token, path cố định — buf[4] BỊ BỎ QUA
}
```

### CMD 0x02 — Handler @ 0x464901

```c
// Không check IsWow64 — luôn dùng Explorer token
sub_4616B0(buf[264], WideStr_from_buf4);
// Hoạt động trên cả 32-bit và 64-bit, path từ buf[4]
```

### CMD 0x03 — Handler @ 0x4647AC

```c
// Logic giống hệt CMD 0x01
if (sub_465DE0() == 1) {
    sub_4625C0(buf[264], WideStr_from_buf4);
} else {
    path = install_dir + L"na_client.exe";
    sub_4616B0(buf[264], path);
}
```

### So sánh và ranking

| | cmd 0x01 | cmd 0x02 | cmd 0x03 |
|---|---|---|---|
| **Token (64-bit)** | **SYSTEM** | Explorer | **SYSTEM** |
| **Token (32-bit)** | Explorer | Explorer | Explorer |
| **Path (64-bit)** | buf[4] ✓ | buf[4] ✓ | buf[4] ✓ |
| **Path (32-bit)** | na_client.exe ✗ | buf[4] ✓ | na_client.exe ✗ |
| Sig check bypass | RSA_NO_PADDING | RSA_NO_PADDING | RSA_NO_PADDING |
| **Rank (64-bit)** | #1 SYSTEM | #3 user | #1 SYSTEM |
| **Rank (32-bit)** | #2 fixed | #1 custom | #2 fixed |

**Kết luận:** Trên 64-bit Windows, dùng cmd 0x01 hoặc 0x03 với `buf[264]=1` và exe có Authenticode RSA ≤ 4096 = RCE as SYSTEM.

---

## CMD 0x04 — DLL Load / RCE as SYSTEM ⚠️ CRITICAL

**Handler:** `0x4636C7`
**Không có signature check trên DLL**

### Code đầy đủ

```c
// Handler @ 0x4636C7
BYTE v127[4096] = {0};    // output buffer
wchar_t LibFileName[...]; // DLL path buffer

// ── Bước 1: Xác định install directory ────────────────────────────────
sub_460670(&LibFileName);   // đọc từ registry HKLM\Software\TopSec\...
if (LibFileName[0] == 0) {
    // Fallback: dùng thư mục của sv_service.exe
    GetModuleFileNameW(NULL, path, MAX_PATH);
    _wsplitpath_s(path, drive, dir, ...);
    wcscpy_s(LibFileName, drive);
    wcscat_s(LibFileName, dir);
}

// ── Bước 2: Build DLL path ─────────────────────────────────────────────
// Tìm null terminator của LibFileName (path kết thúc bằng '\')
// rồi append "secChecker.dll"
qmemcpy(end_of_path, L"\\secChecker.dll", 0x20);
// → LibFileName = "C:\Program Files (x86)\NGVONE\Client\secChecker.dll"

// ── Bước 3: Load và call DLL ───────────────────────────────────────────
HMODULE hDll = LoadLibraryW(LibFileName);
// LoadLibraryW chạy DllMain với DLL_PROCESS_ATTACH

BOOL (*fn_init)(char*) = GetProcAddress(hDll, "init");
BOOL initOk = fn_init(&buf[288]);
// init() nhận argument từ buf[288] (MBCS string hoặc NULL)

if (initOk) {
    DWORD* (*fn_check)(BYTE*) = GetProcAddress(hDll, "checkAllSecurity");
    DWORD *ret = fn_check(v127);
    // ret = &g_size trong DLL; *(ret - 4) = actual byte count
    // Convention: checkAllSecurity ghi vào v127, trả pointer tới size field

    DWORD dataLen = *(ret - 4);  // số bytes output thực sự
    // encode và gửi về
    DWORD b64Len = sub_465BF0(dataLen);  // base64 encode
    sendto(s, v131, b64Len, 0, &from, 16);
}
```

### Tại sao path DLL hardcode là "secChecker.dll"?

Đây là tên DLL của Topsec security scanner. sv_service.exe được thiết kế để load DLL này và gọi các hàm security check. Attacker chỉ cần drop DLL với đúng tên và export vào install dir, thì service tự load.

**Tại sao không nhận path DLL từ packet?** Design choice — developer muốn đảm bảo chỉ DLL từ install dir được load. Thực ra đây không phải security feature vì install dir thường writable bởi local admin.

### Tại sao output là Base64?

DLL có thể output binary data (hex bytes, hashes, raw bytes). UDP packet là binary protocol, nhưng caller có thể là client GUI không handle binary well. Base64 đảm bảo output là printable ASCII, safe qua mọi text processing. `sub_465BF0` là custom base64 encoder embedded trong service.

### DLL export convention

```c
// DLL phải export 2 hàm:

BOOL __cdecl init(char *arg) {
    // arg = &buf[288] từ packet (có thể NULL/empty)
    // Khởi tạo DLL, return TRUE để tiếp tục
    // return FALSE → service không gọi checkAllSecurity, không gửi gì
    return TRUE;
}

DWORD* __cdecl checkAllSecurity(unsigned char *outbuf) {
    // outbuf = buffer 4096 bytes trong service process space
    // Ghi kết quả vào outbuf
    // Return: pointer tới DWORD g_size
    // Service đọc: *(ret - 4) = số bytes thực sự đã ghi

    static DWORD g_size;  // service đọc &g_size - 4 bytes
    g_size = write_output(outbuf);
    return &g_size;
    // Convention weird: service tính *(ret_ptr - 4) bytes
    // Thực ra: outbuf được ghi, và length ở DWORD trước g_size trong memory layout
}
```

**Tại sao convention `*(ret - 4)` kỳ lạ vậy?** Đây có thể là artifact của C++ allocator — khi `operator new` allocate, nó thường ghi size tại `ptr - 4`. Service code dùng `*v33 - 4` tức là `*(DWORD*)(v33) - 4 bytes` — có thể là bug hoặc một convention internal của Topsec.

### Tại sao không có sig check cho DLL?

Không có call nào đến `sub_462490` trước khi `LoadLibraryW`. Developer chỉ check signature của exe (cmd 0x01-0x03), không check DLL. Lý do có thể: DLL được coi là "internal component" trong install dir, không phải user-provided exe. Đây là attack surface không có protection.

---

## CMD 0x05 — Hosts File Injection (DNS Poisoning)

**Handler:** `0x463049`

### Tại sao cần 2 fields (buf[284] và buf[288])?

```
buf[284:288] = DWORD: số bytes DNS entries
buf[288:292] = DWORD: 1 (trigger flag, bắt buộc)
buf[296:]    = DNS entries data
```

`buf[288]` = trigger flag. Handler check `if (*DWORD@buf[288] != 1) goto skip` — nếu không có flag này, service skip hoàn toàn. Đây là "intent confirmation" để tránh ghi nhầm hosts file nếu packet corrupt. `buf[284]` = length của data thực sự tại `buf[296]`.

### Tại sao có 2 mode: append và replace?

```c
char *marker = strstr(current_hosts, "#Add by VONE SSL VPN Client");

if (!marker) {
    // Hosts file chưa có VPN entries → APPEND vào cuối
    // Thêm block mới với marker header/footer
} else {
    // Hosts file đã có block cũ → REPLACE nội dung block
    // Giữ phần trước marker, thay nội dung, giữ phần sau footer
}
```

Marker `#Add by VONE SSL VPN Client` là "ownership tag" — cho phép service update DNS entries của mình mà không ảnh hưởng đến entries khác trong hosts file. Idempotent design: gọi nhiều lần chỉ update, không duplicate.

**Attack potential:** Nếu hosts file hiện tại không có marker, service append mà không backup kiểm tra integrity. Nếu DNS entry của attacker được inject trước marker của Topsec, chúng không bị overwrite bởi cmd replace.

### Tại sao backup hosts.bak?

`CopyFileW(hosts → hosts.bak)` chạy trước khi write. Cmd 0x06 restore từ backup. Đây là safety net của Topsec khi VPN ngắt kết nối — restore DNS về state trước khi VPN connect. Attacker có thể dùng cmd 0x06 để xóa dấu vết sau khi hoàn thành attack.

---

## CMD 0x06 — Restore Hosts File

**Handler:** `0x46350B`

```c
GetSystemDirectoryW(sysdir);
// hosts     = sysdir + "\\drivers\\etc\\hosts"
// hosts_bak = sysdir + "\\drivers\\etc\\hosts.bak"

CopyFileW(hosts_bak, hosts, FALSE);  // overwrite hosts bằng backup
_wremove(hosts_bak);                 // xóa backup sau khi restore
```

Không có response. Anti-forensics: xóa backup sau khi restore đảm bảo không còn evidence của DNS injection trước đó.

---

## CMD 0x07 — Heartbeat / Ping

**Handler:** `0x463AF2`

```c
memset(v131, 0, 4096);
v131[0] = 8;                               // response byte
sendto(s, v131, 284, 0, &from, 16);        // 284 bytes
```

**Tại sao response là 284 bytes?** 284 = 0x11C. Không rõ lý do chính xác — có thể là size của một internal struct. Tất cả byte sau index 0 đều là 0x00.

---

## CMD 0x09 / 0x0A / 0x0B / 0x0C / 0x0D — Get Install Directory

**Handler:** `0x464BDA` (5 case cùng một code)

```c
sub_460670(&Buffer);  // đọc install dir từ registry
// sub_460670 @ 0x460670:
//   RegOpenKeyW(HKLM, "Software\TopSec\SVClientForNG")
//   RegQueryValueExW(key, "ClientDirPath", ...) → UTF-16LE path
//   Trả "C:\Program Files (x86)\NGVONE\Client\"

// Convert UTF-16LE → MBCS
v88 = sub_45A260(..., &Buffer, ...);
memmove(v118, v88, strlen(v88));
sendto(s, v118, 260, 0, &from, 16);
```

**Tại sao 5 case chạy cùng code?** Có thể là 5 loại client (SV, IV, ...) cần lấy install dir nhưng về sau được merge implementation. Response là 260 bytes — đủ cho MAX_PATH MBCS string.

**Info leak value:** Biết install dir giúp xác định path để drop secChecker.dll cho CMD 0x04.

---

## CMD 0x0F / 0x10 — SrvRunFlag

**Handler 0x0F:** `0x463B55` — `sub_462D80(1)`
**Handler 0x10:** `0x463B7A` — `sub_462D80(0)` + cleanup

```c
// sub_462D80 @ 0x462D80:
HKEY key;
RegOpenKeyW(HKEY_LOCAL_MACHINE,
    L"Software\\TopSec\\SVClientForNG", &key);

if (arg == 1) {
    // Chỉ set nếu chưa có (không overwrite)
    if (RegQueryValueExW(key, L"SrvRunFlag", ...) != ERROR_SUCCESS) {
        RegSetValueExW(key, L"SrvRunFlag", 0, REG_SZ, L"y", 4);
    }
} else {
    RegDeleteValueW(key, L"SrvRunFlag");
}
```

**Mục đích:** `SrvRunFlag` là shared state giữa service và client GUI — cho phép client biết service đang chạy. cmd 0x10 còn xóa `srv.cfg` và copy log file — cleanup khi VPN disconnect.

---

## CMD 0x11 — Arbitrary File Copy (SYSTEM File Read Primitive)

**Handler:** `0x463CDA`

```c
// Đọc source path từ packet
memmove(&MultiByteStr, &buf[288], *DWORD@buf[284]);
// MultiByteStr = đường dẫn file nguồn (MBCS)

// Build destination path
sub_460670(&Buffer);           // install dir
wcscat_s(&Buffer, L"\\srv.cfg");

// Convert path MBCS → UTF-16LE
wchar_t *wSrcPath = sub_45FE50(..., &MultiByteStr, ...);

// Copy file — chạy as SYSTEM, không có response
CopyFileW(wSrcPath, Buffer, FALSE);
// FALSE = overwrite nếu srv.cfg đã tồn tại
```

### Tại sao đây là file read primitive?

sv_service.exe chạy as SYSTEM — `NT AUTHORITY\SYSTEM` có `FULL_CONTROL` trên hầu như mọi file trừ OS-locked files. Khi copy sang `install_dir\srv.cfg`, file mới này nằm trong `C:\Program Files (x86)\NGVONE\Client\` — thư mục có thể đọc bởi mọi user (permission mặc định của Program Files là world-readable).

### Tại sao không có response?

Handler kết thúc ngay sau `CopyFileW`, không có `sendto()`. Fire-and-forget design — caller biết nó sẽ thành công vì SYSTEM luôn có quyền. Attacker đọc kết quả trực tiếp từ disk.

### Files có thể đọc

```
CÓ THỂ copy (không bị OS lock):
  C:\Windows\repair\SAM                 ← offline SAM backup (password hashes)
  C:\Windows\repair\SYSTEM             ← offline SYSTEM hive (cần để decrypt SAM)
  C:\Users\<user>\.ssh\id_rsa          ← SSH private key
  C:\Users\<user>\.ssh\id_ed25519      ← SSH private key
  C:\ProgramData\ssh\ssh_host_rsa_key  ← SSH host key
  Mọi file config, database, key file không bị lock

KHÔNG THỂ copy (bị OS lock khi đang chạy):
  C:\Windows\System32\config\SAM        ← live SAM (locked bởi lsass.exe)
  C:\Windows\System32\config\SYSTEM    ← live SYSTEM hive
  NTUSER.DAT của user đang login
  Database files của SQL Server, etc.
```

**Tại sao repair\SAM không bị lock?** `C:\Windows\repair\` chứa backup tạo khi run `%SystemRoot%\System32\repair\setup.log`. Đây là file static, không được mount bởi OS registry system, nên không có lock.

### Chain attack với CMD 0x04

```
Step 1: cmd 0x11 copy "C:\Windows\repair\SAM" → install_dir\srv.cfg
Step 2: secChecker.dll mở và đọc install_dir\srv.cfg
Step 3: cmd 0x04 → DLL output SAM bytes → base64 → UDP response
```

---

## CMD 0x12 — Close SVClient Window

**Handler:** `0x463DDD`

```c
HWND hwnd = FindWindowW(NULL, L"SVClient");
if (hwnd) {
    DWORD lParam[3] = {255, 0, 0};
    SendMessageW(hwnd, 0x4A, 0xFF, (LPARAM)lParam);
    // Message 0x4A = WM_USER + 10 = custom "please shutdown" message
    // Topsec VPN client handle message này để graceful shutdown
}

// Wait for client to fully exit
for (int i = 0; i < 120; i++) {  // max 60 seconds
    HANDLE h = OpenMutexW(MUTEX_ALL_ACCESS, 0, L"Global\\MUTEX_VONE_NA_FOR_NG");
    if (!h) break;              // mutex released = client đã exit
    CloseHandle(h);
    Sleep(500);
}

v131[0] = 0x13;
sendto(s, v131, 284, 0, &from, 16);
```

**Tại sao dùng mutex để check?** VPN client giữ mutex `Global\MUTEX_VONE_NA_FOR_NG` khi đang chạy và release khi exit. Service poll mutex mỗi 500ms — khi không open được → client đã thoát. Timeout 60s (120 × 500ms).

**Network timeout:** Socket timeout phải > 60s khi gọi cmd này, nếu không recv sẽ timeout trước khi service gửi response.

---

## CMD 0x16 — Mainboard Serial Hash

**Handler:** `0x4639FD`

```c
char serial[256], base64_md5[256];
sub_45E4E0(serial, &success);
// sub_45E4E0: WMI query "SELECT SerialNumber FROM Win32_BaseBoard"

if (success) {
    // MD5(serial) → Base64 → sendto
    MD5(serial, strlen(serial), digest);
    base64_encode(digest, 16, base64_md5);
    sendto(s, base64_md5, strlen(base64_md5), ...);
}
```

**Mục đích thiết kế:** License enforcement — VPN client định danh máy tính theo hardware serial để validate license. Attacker dùng để fingerprint máy victim và tạo signature duy nhất.

---

## CMD 0x17 — Set Log Level

**Handler:** `0x463F0F`

```c
int level = (uint8_t)buf[1];  // 0-255 nhưng thực tế dùng 0-5
SetLogLevel(level);            // @ 0x483340: ghi vào global DWORD
GetLogLevel(&current);         // @ 0x48333C: đọc lại global DWORD
if (level == current)
    sprintf(v131, "%d", 0);    // "0" = success
else
    sprintf(v131, "%d", -1);   // "-1" = fail
sendto(s, v131, strlen(v131), ...);
```

**Attack use:** Set level = 0 để disable logging trước khi exploit, giảm evidence.

---

## CMD 0x18 — Kill TopSap.exe

**Handler:** `0x46402D`

```c
sub_461010(L"TopSap.exe");
// sub_461010 @ 0x461010:
//   snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
//   Process32FirstW, Process32NextW loop:
//     if StrCmpNIW(L"TopSap.exe", pe.szExeFile) == 0:
//         h = OpenProcess(PROCESS_TERMINATE, FALSE, pid)
//         TerminateProcess(h, 0)
//   return 0;  ← LUÔN trả 0 bất kể có kill được không

// Check kết quả của sub_461010:
if (sub_461010(...) != 0)   // KHÔNG BAO GIỜ đúng vì luôn return 0
    sprintf(v131, "%d", -1)
else
    sprintf(v131, "%d", 0)  // → LUÔN gửi "0"
sendto(...)
```

**Bug:** `sub_461010` luôn return 0 ở cuối function bất kể kill thành công hay thất bại. Handler check `if (ret != 0)` → condition never true → response luôn là `"0"` dù process không tồn tại.

---

## CMD 0x19 — Write HKLM\SOFTWARE\Topsec\FilePath

**Handler:** `0x4640F6`

```c
// Khởi tạo response = "-1"
sprintf(v131, "%d", -1);

HKEY key;
LONG v51 = RegOpenKeyW(HKEY_LOCAL_MACHINE,
                        L"SOFTWARE\\Topsec",  // WoW64: → WOW6432Node\Topsec
                        &key);

if (v51 != 0) {
    log("RegOpenKey Failed error[%d]", v51);
    // BUG: KHÔNG return! Fall through đến code bên dưới
}
// nếu v51 != 0, key = invalid handle nhưng code vẫn tiếp tục

if (v51 == 0) {
    // Đọc giá trị cũ (chỉ để log)
    RegQueryValueExW(key, L"FilePath", ...);  // log result
    
    // Ghi giá trị mới từ buf[4]
    LONG v53 = RegSetValueExW(
        key, L"FilePath", 0,
        REG_SZ,             // BUG: REG_SZ cần UTF-16LE, nhưng buf[4] là MBCS
        (BYTE*)&buf[4],     // attacker-controlled value
        strlen(&buf[4]) + 1
    );
    if (v53 != 0) {
        log("RegSetValue Failed");
        RegCloseKey(key);   // Close #1
        // BUG: không return, tiếp tục xuống
    }
}

// Code này LUÔN chạy dù open fail hay set fail:
log("RegSetValue Success");  // log sai khi thực ra fail
sprintf(v131, "%d", 0);      // override response = "0" dù fail
RegCloseKey(key);            // Close #2 — double-close nếu v53 != 0
sendto(s, v131, strlen(v131), ...);
```

**Bug 1 — Fall through khi open fail:** Khi `RegOpenKeyW` fail, `key` = garbage/NULL, nhưng code tiếp tục và gọi `RegCloseKey(garbage)` — undefined behavior.

**Bug 2 — Double RegCloseKey:** Nếu `RegSetValueExW` fail, `RegCloseKey(key)` được gọi tại Close #1, sau đó Close #2 lại gọi lần nữa với handle đã đóng — undefined behavior, có thể double-free.

**Bug 3 — REG_SZ với MBCS bytes:** `RegSetValueExW` với `REG_SZ` expect UTF-16LE data. Code truyền MBCS bytes từ buf[4] — characters sẽ bị interpret sai trên non-ASCII values.

**Bug 4 — Response luôn "0":** `sprintf(v131, "%d", 0)` override bất kể thành công hay thất bại → caller không thể biết có thực sự thành công không.

---

## CMD 0x1A — Set HKCR\.css Content Type

**Handler:** `0x4642D4`

```c
HKEY hKey;
if (RegOpenKeyW(HKEY_CLASSES_ROOT, L".css", &hKey) == 0) {
    RegSetValueExW(hKey, L"Content Type", 0,
                   REG_SZ, L"text/css", 0x10);  // 0x10 = 16 bytes
    RegCloseKey(hKey);
}
sprintf(v131, "%d", 0);
sendto(...);  // response luôn "0"
```

**Mục đích:** VPN client web interface serve CSS files — cần đúng MIME type để browser render. Nếu `HKCR\.css\Content Type` bị xóa/sai, web interface bị broken.

---

## CMD 0x1B — Kill na_client.exe

**Handler:** `0x463FFC`

```c
WinExec("TASKKILL /F /IM na_client.exe /T", SW_HIDE);
// /F = force, /IM = by image name, /T = kill child processes too
// SW_HIDE = không hiện cửa sổ cmd
```

**Tại sao dùng WinExec thay vì sub_461010?** WinExec spawn cmd.exe với TASKKILL — đơn giản hơn nhưng tạo child process visible trong process list. `sub_461010` dùng trực tiếp `TerminateProcess` — no child process, tàng hình hơn. Developer có thể dùng WinExec cho na_client.exe vì muốn kill child processes (`/T`) mà sub_461010 không làm được.

---

## CMD 0x1C — Spawn VPN NIC Reset Thread

**Handler:** `0x4643EA`

```c
_beginthread(sub_465E30, 0, NULL);
// sub_465E30 @ 0x465E30 runs in new thread:
```

```c
void sub_465E30(void *unused)
{
    Sleep(1000);
    
    // Check xem NA_CLIENT.EXE có đang chạy không
    if (!sub_45DEA0(L"NA_CLIENT.EXE")) return;
    
    // Lấy VPN connection status từ shared memory
    SHMEM_GetRunTimeSHMMStatus();
    int status = sub_466240(v8, ...);
    if (status != 1 || v8[2] == 2) return;  // kết nối OK, không cần reset

    // Thử reconnect 3 lần
    int retry = 0;
    while (retry < 3 && !sub_466080()) retry++;

    if (retry == 3) {
        // Vẫn lỗi sau 3 lần → hard reset
        WinExec("TASKKILL /F /IM na_client.exe /T", 0);
        
        // Disable/enable VPN virtual NIC
        char cmd[512];
        sprintf(cmd, "%s\\instdrv.exe disable *TOPSEC_VNIC", sysdir);
        sub_4604D0(cmd);  // chạy instdrv.exe

        sprintf(cmd, "%s\\instdrv.exe enable *TOPSEC_VNIC", sysdir);
        sub_4604D0(cmd);
    }
}
```

**instdrv.exe** là driver installation tool của Topsec, có thể enable/disable virtual NIC (`TOPSEC_VNIC`) trong Device Manager.

---

## CMD 0x1D — Reset Log Files

**Handler:** `0x464405`

```c
char sysdir[MAX_PATH];
GetSystemDirectoryA(sysdir);  // "C:\Windows\System32"

// Truncate TopsecVpnSvc.log
char path[512];
snprintf(path, sizeof(path), "%s\\TopsecVpnSvc.log", sysdir);
FILE *f = fopen(path, "wb+");   // "wb+" = create or truncate, binary write
fwrite("[New Log]\n", 10, 1, f);
fclose(f);

// Truncate TopsecVpnClient.log
snprintf(path, sizeof(path), "%s\\TopsecVpnClient.log", sysdir);
f = fopen(path, "wb+");
fwrite("[New Log]\n", 10, 1, f);
fclose(f);

// Xóa backup file
char bak[512];
snprintf(bak, sizeof(bak), "%s.bak", path);
remove(bak);  // xóa TopsecVpnClient.log.bak
```

**Tại sao log ở System32?** Service (SYSTEM) có quyền write vào `System32`, còn user thường thì không. Log files để trong `System32` đảm bảo chỉ service và admin mới đọc/sửa được. Điều này cũng có nghĩa là attacker (có thể invoke service qua UDP) có thể xóa evidence.

---

## CMD 0x14 — Launch Process with Command Line

**Handler:** `0x464A95`

```c
log("ITEM_TYPE_CUSTOM_IE_WITH_PARAM");

// buf[4] = exe path
// buf[284] = command line parameters (vùng khác, không phải data length thông thường)
MultiByteToWideChar(... &buf[4]   → WideStr_exe);
MultiByteToWideChar(... &buf[284] → WideStr_cmdline);

// sub_461D40 cũng call sub_462490 (signature check) trước khi spawn
sub_461D40(buf[264], WideStr_exe, WideStr_cmdline);
```

Khác với cmd 0x01-0x03, cmd 0x14 cho phép truyền cả command line argument. Nếu exe pass được sig check (RSA_NO_PADDING bypass), attacker có thể control cả exe path lẫn arguments.

---

## CMD 0x00 — IV/SV Bootstrap Launch (buf[4] empty)

**Handler:** inline in `StartAddress @ 0x462EB0`, reached only when **`strlen(&buf[4]) == 0`**

This is a separate dispatcher path distinct from CMD 0x01/0x02/0x03. When the client sends a packet with `buf[0]` = 0 or 1 and leaves `buf[4]` empty (no exe path), the service takes this branch instead.

```c
// Reached when strlen(&buf[4]) == 0
if (sub_4615F0() == 0)
    goto LABEL_174;  // "Unknown item type" — install check failed

if (buf[0] == 0) {
    // IV mode
    sub_461B80();   // spawn install_dir\SecPkgCpl.exe
    sub_461CE0();   // spawn install_dir\LoadCert.exe
} else if (buf[0] == 1) {
    // SV mode
    sub_461C50();   // spawn install_dir\AxService.exe
} else {
    goto LABEL_174; // unknown, discard
}
```

**Field mapping:**

| Field | Value | Meaning |
|---|---|---|
| `buf[0]` | 0 | IV mode — launch `SecPkgCpl.exe` + `LoadCert.exe` |
| `buf[0]` | 1 | SV mode — launch `AxService.exe` |
| `buf[4]` | `""` (empty) | Required to reach this path |

**Tại sao buf[4] rỗng lại đến path này?**

Dispatcher kiểm tra `strlen(&buf[4])` trước khi vào switch cho CMD 0x01/0x02/0x03. Khi buf[4] trống, dispatcher nhảy sang branch này — thiết kế "default launch" cho installer/service manager. Client chỉ cần nói "launch IV" hoặc "launch SV", service tự biết path hardcoded từ install_dir. Điều này tách biệt rõ "attacker-controlled path" (buf[4] non-empty) vs "trusted hardcoded path" (buf[4] empty).

**Security note:** `sub_4615F0()` là guard duy nhất. Nếu install check pass (thường xuyên), bất kỳ UDP client nào cũng có thể trigger re-launch của `SecPkgCpl.exe`, `LoadCert.exe`, hoặc `AxService.exe`. Không có signature check vì paths là hardcoded — service tin tưởng file trong install_dir. Nếu attacker đã ghi được vào install_dir (qua CMD 0x04 SYSTEM RCE chain), các exe này có thể đã bị trojanized.

---

## CMD 0x15 — NO-OP (Dead Code)

**Handler:** `case 0x15: goto LABEL_213` (trong inner switch, khi `strlen(&buf[4]) > 0`)

```c
// Dispatcher code (StartAddress @ 0x462EB0):
switch (buf[0]) {
    case 0x14: sub_461D40(...); break;
    case 0x15: goto LABEL_213;   // <-- rơi thẳng xuống recvfrom loop
    default:   log("Unknown item type, type is %d!", buf[0]); goto LABEL_213;
}
// LABEL_213 = tiếp tục recvfrom, không làm gì, không gửi response
```

**Hành vi:** Service nhận packet có `buf[0]=0x15` và `strlen(&buf[4]) > 0`, vào case 0x15, `goto LABEL_213` — quay lại `recvfrom` ngay lập tức. Không log, không response, không side effect.

**Tại sao tồn tại?** Đây là reserved slot trong protocol — developer đã `case 0x15:` để giữ chỗ cho một tính năng tương lai nhưng chưa implement body. Khác với `default:` case (in log "Unknown item type"), CMD 0x15 thậm chí không log — ngụ ý nó được biết đến nhưng intentionally để trống.

**Security impact:** Không có. Packet CMD 0x15 bị service bỏ qua hoàn toàn.

---

## Commands Không Implement (Protocol Gaps)

Các command byte sau **không có handler** trong dispatcher — rơi vào `default:` → log `"Unknown item type, type is %d!"` → discard packet:

| Cmd | Decimal | Trạng thái |
|-----|---------|------------|
| 0x08 | 8 | Không có case — unimplemented |
| 0x0E | 14 | Không có case — unimplemented |
| 0x13 | 19 | Không có case — unimplemented |

**Tại sao biết chắc?** Kiểm tra toàn bộ `StartAddress` (0x462EB0): outer switch có cases 7,9–13,15–18,22–29; inner switch có cases 1–3,0x14,0x15. Không có case 8, 14, 19 ở bất kỳ đâu. Gửi packet với các bytes này chỉ sinh ra log entry phía service, không có action.

---

## Tổng hợp Attack Surface

| Lỗ hổng | Cmd | Handler | Impact | Auth cần |
|---|---|---|---|---|
| **RCE as SYSTEM + output** | 0x04 | 0x4636C7 | Load DLL tùy ý, output qua UDP | Không |
| **RCE as SYSTEM process** | 0x01/0x03 | 0x4647AC+ | Spawn SYSTEM process với path tùy ý | Sig RSA≤4096 |
| **RCE as Explorer user** | 0x02 | 0x464901 | Spawn user process với path tùy ý | Sig RSA≤4096 |
| **File read as SYSTEM** | 0x11 | 0x463CDA | Copy bất kỳ file → install_dir\srv.cfg | Không |
| **DNS Poisoning** | 0x05 | 0x463049 | Ghi hosts file → redirect traffic | Không |
| Registry HKLM write | 0x19 | 0x4640F6 | Ghi HKLM\SOFTWARE\WOW6432Node\Topsec\FilePath | Không |
| Registry HKCR write | 0x1A | 0x4642D4 | Ghi HKCR\.css\Content Type | Không |
| Process kill | 0x18 | 0x46402D | Kill TopSap.exe (TerminateProcess) | Không |
| Process kill | 0x1B | 0x463FFC | Kill na_client.exe (TASKKILL /F /T) | Không |
| VPN NIC disable | 0x1C | 0x4643EA | instdrv disable/enable *TOPSEC_VNIC | Không |
| Hosts restore | 0x06 | 0x46350B | Restore hosts.bak (xóa evidence) | Không |
| Info leak | 0x09 | 0x464BDA | Install directory path | Không |
| Info leak | 0x16 | 0x4639FD | Mainboard serial hash | Không |
| Log wipe | 0x1D | 0x464405 | Truncate TopsecVpnSvc/Client.log | Không |

### Attack Chain tối ưu (64-bit Windows)

```
Recon:
  CMD 0x07 → verify service chạy
  CMD 0x09 → lấy install_dir path

Privilege Escalation:
  CMD 0x01 (buf[264]=1) → spawn SYSTEM process
    → SYSTEM process drop secChecker.dll vào install_dir
  CMD 0x04 → load DLL → checkAllSecurity() → kết quả qua UDP

Hoặc (không cần signed exe):
  CMD 0x11 → copy target file → install_dir\srv.cfg
  Đọc install_dir\srv.cfg trực tiếp từ disk

Cleanup:
  CMD 0x1D → wipe logs
  CMD 0x06 → restore hosts (nếu đã poison)
```

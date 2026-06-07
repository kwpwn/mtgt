# Detection and Defense — Network Blocking EDR Evasion

## Overview (Blue Team Perspective)

This document consolidates detection strategies and hardening recommendations for
all network blocking techniques covered in this module. Understanding the attack
side is necessary to build effective defenses.

---

## Detection Matrix

| Technique | Primary Detection | Secondary Detection | Blind Spots |
|---|---|---|---|
| WFP Filter Injection | Event 5447 (add) | WFPExplorer enumeration | Attacker disables auditing first |
| WFP Filter Deletion | Event 5447 (delete) | Baseline diff | Same |
| 360WFP BYOVD | Event 7045 (driver load) | DeviceIoControl ETW | 360 installed → normal load |
| WinDivert EDRPrison | Event 7045 (driver load) | WFP callout list | Renamed driver |
| QoS Throttling | Registry change | QoS policy audit log | No WFP events |
| Custom Callout | Events 5446+5447 | Driver hash scan | Signed driver |

---

## Detection Implementation

### 1. Windows Event Log — Enable WFP Auditing

By default, WFP filter change auditing is **disabled**. Enable it:

```powershell
# Enable WFP audit policy
auditpol /set /subcategory:"Filtering Platform Policy Change" /success:enable /failure:enable

# Verify
auditpol /get /subcategory:"Filtering Platform Policy Change"
```

Events to monitor (Security event log):
```
5446 — WFP callout changed (added/removed/modified)
5447 — WFP filter added/deleted/modified
5448 — WFP provider changed
5449 — WFP provider context changed
5450 — WFP sublayer changed
```

### 2. SIEM Rules (Sigma format)

```yaml
# Detect WFP filter addition with BLOCK action
title: Suspicious WFP Block Filter Addition
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5447
        Action: 'Add'
        'Action Type': 'Block'
    filter_legitimate:
        # Exclude Windows Firewall service
        ProcessName|contains: 'svchost.exe'
        ServiceSid: 'S-1-5-80-...'  # BFE service SID
    condition: selection and not filter_legitimate
```

```yaml
# Detect QoS policy creation for security processes
title: QoS Policy Throttling Security Process
status: experimental
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13  # Registry value set
        TargetObject|contains: 'SOFTWARE\Policies\Microsoft\Windows\QoS'
        Details|contains:
            - 'MsMpEng'
            - 'MsSense'
            - 'csfalcon'
            - 'elastic'
    condition: selection
```

### 3. Periodic WFP Baseline Comparison

```powershell
# Snapshot current WFP filter state
netsh wfp show filters file=wfp_baseline.xml

# Later: compare against baseline
netsh wfp show filters file=wfp_current.xml
# Use XML diff to identify additions/removals
```

Or use `EDRNoiseMaker` / `Get-WfpFilterData` PowerShell module for structured output.

### 4. Monitor Registry QoS Keys

```powershell
# One-time check: list QoS policies with suspicious throttle rates
Get-ChildItem "HKLM:\SOFTWARE\Policies\Microsoft\Windows\QoS" | ForEach-Object {
    $rate = (Get-ItemProperty $_.PSPath)."Throttle Rate"
    $app  = (Get-ItemProperty $_.PSPath)."Application Name"
    if ($rate -lt 10000) {
        Write-Warning "Suspicious QoS policy: $app throttled to $rate bps"
    }
}
```

Use Sysmon Event 13 (registry value set) to monitor in real time.

### 5. Monitor for Known Vulnerable Drivers

Use a blocklist of known BYOVD driver hashes. Microsoft maintains:
`https://github.com/microsoft/vulnerable-driver-blocklist`

```powershell
# Check loaded drivers against blocklist
$loadedDrivers = Get-WmiObject Win32_SystemDriver | Select-Object Name, PathName
# Compare hashes against known vulnerable driver list
```

### 6. EDR Self-Healing Heartbeat

EDRs should implement a connectivity watchdog:
```
Every 30 seconds:
    1. Try TCP connect to primary C2
    2. If fails 3 consecutive times:
        a. Log locally (Windows Event Log, local syslog)
        b. Send alert via alternative channel (email, SMS if configured)
        c. Log: enumerate WFP filters, dump QoS registry keys
        d. Attempt to restore self-protection filters
```

---

## Hardening Recommendations

### For EDR Vendors

1. **Use max-weight filters + CLEAR_ACTION_RIGHT**  
   ```c
   filter.weight.uint64 = 0xFFFFFFFFFFFFFFFF;
   filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
   ```
   This prevents any user-mode filter from overriding the EDR's permit rule.

2. **Use terminating callouts** for self-protection, not simple filters.  
   Callout verdicts with `~FWPS_RIGHT_ACTION_WRITE` cannot be overridden by any
   non-callout filter.

3. **Monitor WFP state for changes** using `FwpsCalloutRegister` callback notifications
   and `FwpmFilterSubscribeChanges` to detect when someone modifies the filter list.

4. **Protect BFE access** — restrict `FwpmEngineOpen0` to known processes via the
   BFE security descriptor.

5. **PPL-protect the agent process** so `OpenProcess(PROCESS_QUERY_INFORMATION)` fails
   for non-PPL callers — preventing path-based filter injection.

6. **Implement connectivity watchdog** and use alternative reporting paths when
   primary C2 is unreachable.

### For SOC / Defenders

1. **Enable WFP auditing** (see above) — ship Events 5446-5450 to SIEM.

2. **Baseline WFP filters** weekly; alert on unexpected additions with Block action.

3. **Monitor QoS registry keys** for throttle values targeting security processes.

4. **Block known BYOVD drivers** via WDAC (Windows Defender Application Control)
   `Deny` rules based on driver hash and/or certificate subject name.

5. **Enable HVCI (Hypervisor-Protected Code Integrity)** — prevents loading unsigned
   or BYOVD kernel drivers:
   ```
   Computer Configuration → Administrative Templates
     → System → Device Guard → Turn on Virtualization Based Security
     → Enable: Secure Boot + DMA Protection + HVCI
   ```
   HVCI breaks most BYOVD attack chains (see `../02_mitigations-vbs-hvci-vtrp/`).

6. **Kernel Control Flow Guard (kCFG)** — makes it harder for malicious drivers to
   hook legitimate kernel functions.

---

## HVCI Impact on Each Technique

| Technique | HVCI Blocks? | Notes |
|---|---|---|
| WFP Filter Injection | **No** | User-mode API; HVCI doesn't prevent |
| WFP Filter Deletion | **No** | Same |
| 360WFP BYOVD | **Partial** | If driver is on blocklist, yes; else driver loads but may crash |
| WinDivert BYOVD | **Partial** | Depends on driver's HVCI compatibility |
| QoS Throttling | **No** | Registry-based; no kernel code |
| Custom Callout (unsigned) | **Yes** | HVCI enforces kernel code signing at hardware level |
| Custom Callout (signed) | **No** | HVCI only blocks unsigned/revoked; valid cert passes |

---

## Summary Priority List (for Blue Team)

Priority 1 — Quick wins (configuration only):
- [ ] Enable WFP audit policy → ship to SIEM
- [ ] Add SIEM rule on Event 5447 action=Block from non-system processes
- [ ] Add Sysmon rule for registry writes under QoS key path

Priority 2 — Medium effort (policy/driver management):
- [ ] Deploy HVCI via WDAC/Group Policy
- [ ] Add BYOVD blocklist (Microsoft vulnerable driver blocklist)
- [ ] Periodic WFP baseline comparison (weekly scheduled task)

Priority 3 — Vendor/architecture (requires EDR-side changes):
- [ ] Ensure EDR uses max-weight + CLEAR_ACTION_RIGHT filters
- [ ] Ensure EDR uses terminating callout for self-protection
- [ ] Implement connectivity watchdog with local fallback logging

---

## Tool References

| Tool | Purpose | URL |
|---|---|---|
| WFPExplorer | GUI WFP filter inspection | `https://github.com/zodiacon/WFPExplorer` |
| EDRNoiseMaker | WFP enumeration + auditing | GitHub search |
| `netsh wfp show` | CLI WFP snapshot | Built-in Windows |
| WDAC Wizard | WDAC policy creation | `https://webapp-wdac-wizard.azurewebsites.net` |
| MS BYOVD blocklist | Vulnerable driver list | `https://github.com/microsoft/vulnerable-driver-blocklist` |

---

Next: `09_references.md`

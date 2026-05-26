# MDE/KQL BYOVD Hunting Patterns

Updated: 2026-05-27

## Purpose

This document gives defensive Microsoft Defender XDR Advanced Hunting patterns for BYOVD and suspicious driver activity.

These are templates, not drop-in detections. Environments differ in table availability, ActionType names, telemetry volume, and retention. Always validate in the portal schema for your tenant.

Safety boundary:

- defensive hunting only,
- no exploit payloads,
- no bypass instructions,
- no driver IOCTL trigger logic.

## Hunting Model

BYOVD activity is usually not one event. It is a timeline:

```text
driver file appears
  -> service key or load mechanism appears
  -> driver load or load attempt occurs
  -> controller process interacts with device
  -> privilege/evasion/crash/telemetry anomaly follows
```

Advanced Hunting often cannot see every private kernel IOCTL. The practical approach is correlation.

## Tables To Consider

| Table | Use |
|---|---|
| `DeviceFileEvents` | `.sys` file creation, rename, modification, downloaded driver artifacts |
| `DeviceProcessEvents` | service-control tools, installers, suspicious controller processes |
| `DeviceRegistryEvents` | service key creation/modification under driver service locations |
| `DeviceEvents` | security-control events and product-specific driver/load signals |
| `DeviceImageLoadEvents` | image load events; validate whether it covers the signal needed in your tenant |
| `DeviceFileCertificateInfo` | signer and certificate enrichment |
| `DeviceInfo` | OS, exposure context, device metadata |

Important nuance:

```text
table existence does not guarantee every driver load is represented as a clean event;
use OS logs, Sysmon, EDR, CI logs, and endpoint triage together
```

## Pattern 1: New `.sys` Files In Unusual Paths

Goal:

```text
find driver binaries written outside normal driver staging paths
```

Template:

```kusto
DeviceFileEvents
| where Timestamp > ago(14d)
| where FileName endswith ".sys"
| where FolderPath !startswith @"C:\Windows\System32\drivers\"
| where FolderPath !contains @"\DriverStore\FileRepository\"
| project Timestamp, DeviceName, FileName, FolderPath, SHA1, SHA256,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

Why:

```text
many legitimate drivers land in standard OS/vendor staging locations;
user-writable or temporary locations deserve review
```

False positives:

- legitimate vendor installers,
- EDR updates,
- lab machines,
- driver development systems.

Tuning:

- allowlist approved deployment tooling,
- baseline normal vendor update paths,
- add signer enrichment.

## Pattern 2: Rare Driver File Names On Servers

Goal:

```text
spot utility drivers that do not belong on server endpoints
```

Template:

```kusto
let Lookback = 30d;
DeviceFileEvents
| where Timestamp > ago(Lookback)
| where FileName endswith ".sys"
| summarize DeviceCount=dcount(DeviceId),
            FirstSeen=min(Timestamp),
            LastSeen=max(Timestamp),
            ExamplePath=any(FolderPath),
            ExampleHash=any(SHA1)
  by FileName
| where DeviceCount <= 3
| order by DeviceCount asc, LastSeen desc
```

Why:

```text
BYOVD candidates are often rare hardware utilities, overclocking tools,
firmware helpers, RGB controllers, or old OEM support drivers
```

Tuning:

- separate workstation and server baselines,
- keep exception owners,
- expire exceptions.

## Pattern 3: Driver Service Registry Creation

Goal:

```text
find new kernel-driver service definitions
```

Template:

```kusto
DeviceRegistryEvents
| where Timestamp > ago(14d)
| where RegistryKey has @"\SYSTEM\CurrentControlSet\Services\"
| where RegistryValueName in~ ("Type", "ImagePath", "Start", "ErrorControl")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName
| order by Timestamp desc
```

Review:

- `Type` value representing a driver service,
- `ImagePath` pointing outside expected directories,
- sudden demand-start driver service,
- service created by script host, archive extractor, unknown installer, or remote admin tool.

## Pattern 4: Service Control Tooling Near Driver Artifacts

Goal:

```text
join driver-looking files with service-control activity
```

Template:

```kusto
let DriverFiles =
    DeviceFileEvents
    | where Timestamp > ago(14d)
    | where FileName endswith ".sys"
    | project DeviceId, DriverTime=Timestamp, DriverFile=FileName,
              DriverPath=FolderPath, DriverHash=SHA1;
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("sc.exe", "powershell.exe", "cmd.exe", "pnputil.exe", "rundll32.exe")
| where ProcessCommandLine has_any ("create", "start", "type=", "kernel", ".sys", "pnputil")
| join kind=innerunique DriverFiles on DeviceId
| where abs(datetime_diff("minute", Timestamp, DriverTime)) <= 60
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          DriverTime, DriverFile, DriverPath, DriverHash
| order by Timestamp desc
```

Why:

```text
BYOVD setup often has a file-write and service-control neighborhood;
neither event alone is enough
```

Tuning:

- add approved software deployment parent processes,
- exclude known driver deployment windows,
- shorten window for high-signal detections.

## Pattern 5: Suspicious Driver File With Signer Enrichment

Goal:

```text
inspect driver files with certificate context
```

Template:

```kusto
let DriverFiles =
    DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FileName endswith ".sys"
    | summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp),
                ExamplePath=any(FolderPath)
      by SHA1, FileName, DeviceId, DeviceName;
DriverFiles
| join kind=leftouter (
    DeviceFileCertificateInfo
    | summarize any(*) by SHA1
) on SHA1
| project FirstSeen, LastSeen, DeviceName, FileName, ExamplePath, SHA1,
          Signer=tostring(Signer), SignatureStatus=tostring(SignatureStatus),
          CertificateSerialNumber=tostring(CertificateSerialNumber),
          Issuer=tostring(Issuer)
| order by LastSeen desc
```

Note:

```text
field names may differ or be unavailable depending on schema version;
verify in the Advanced Hunting schema reference
```

Why:

```text
a valid signature is not proof of safety,
but signer and certificate metadata are critical for triage
```

## Pattern 6: Known Vulnerable Driver Names

Goal:

```text
start with known public BYOVD families,
then validate hash and version before action
```

Template:

```kusto
let KnownDriverNames = dynamic([
  "rtcore64.sys",
  "dbutil_2_3.sys",
  "gdrv.sys",
  "winring0x64.sys",
  "winio64.sys",
  "msio64.sys",
  "lnvmsrio.sys",
  "eneio64.sys",
  "pstrip64.sys"
]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where tolower(FileName) in (KnownDriverNames)
| project Timestamp, DeviceName, FileName, FolderPath, SHA1, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

Why:

```text
name-based matching is weak,
but it is useful for initial sweeps and legacy hygiene
```

Validation:

- check hash against LOLDrivers or vendor advisory,
- inspect signer and version resource,
- confirm loadability under current policy,
- check whether a matching service exists,
- confirm device exposure.

## Pattern 7: Security Control State Changes Near Driver Activity

Goal:

```text
find driver artifact activity near security-control changes
```

Template:

```kusto
let DriverWindow =
    DeviceFileEvents
    | where Timestamp > ago(14d)
    | where FileName endswith ".sys"
    | project DeviceId, DriverTime=Timestamp, DriverFile=FileName, DriverPath=FolderPath;
DeviceEvents
| where Timestamp > ago(14d)
| where ActionType has_any ("Antivirus", "Tamper", "Exploit", "Protection", "Security")
| join kind=innerunique DriverWindow on DeviceId
| where abs(datetime_diff("minute", Timestamp, DriverTime)) <= 120
| project Timestamp, DeviceName, ActionType, AdditionalFields,
          DriverTime, DriverFile, DriverPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

Why:

```text
defense evasion often creates contradictions around security-control state,
telemetry volume, service health, or crash timing
```

Tuning:

- replace ActionType filters with tenant-validated values,
- include product-specific alerts,
- join with service crash and reboot telemetry where available.

## Pattern 8: Controller Process Suspicion

Goal:

```text
find unusual userland controllers around driver setup
```

Template:

```kusto
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ProcessCommandLine has_any (".sys", @"\Device\", @"\\.\", "DeviceIoControl", "driver", "kernel")
| where FileName !in~ ("msiexec.exe", "trustedinstaller.exe")
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine,
          ProcessIntegrityLevel, ProcessTokenElevation,
          AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

Why:

```text
private device interaction is not always directly visible,
but controller command lines, tool names, and nearby service activity can be useful pivots
```

False positives:

- developer machines,
- driver test labs,
- legitimate diagnostics,
- EDR or inventory tooling.

## Pattern 9: Crash Or Reboot Neighborhood

Goal:

```text
find machines where driver activity is followed by instability
```

Template:

```kusto
let DriverActivity =
    DeviceFileEvents
    | where Timestamp > ago(14d)
    | where FileName endswith ".sys"
    | project DeviceId, DriverTime=Timestamp, DriverFile=FileName, DriverPath=FolderPath;
DeviceEvents
| where Timestamp > ago(14d)
| where ActionType has_any ("Crash", "BugCheck", "Shutdown", "Restart", "BlueScreen")
| join kind=innerunique DriverActivity on DeviceId
| where Timestamp between (DriverTime .. DriverTime + 1d)
| project Timestamp, DeviceName, ActionType, AdditionalFields,
          DriverTime, DriverFile, DriverPath
| order by Timestamp desc
```

Note:

```text
ActionType strings are tenant/schema dependent.
If this returns nothing, pivot through event logs, WER, EDR alerts, or crash dump collection.
```

## Pattern 10: Blocklist And Policy Exceptions

Goal:

```text
identify endpoints that need policy review before BYOVD hunting conclusions
```

Questions to join from your management stack:

- Is Microsoft vulnerable driver blocklist enabled?
- Is Memory Integrity/HVCI enabled?
- Is WDAC active?
- Are there driver allowlist exceptions?
- Are test signing or kernel debugging settings allowed on this device class?

Why:

```text
same driver has different risk depending on policy state
```

## Triage Worksheet

For every hit, record:

```text
device:
driver file:
path:
hash:
signer:
first seen:
service key:
load evidence:
controller process:
account:
business owner:
known vulnerable status:
blocklist state:
HVCI state:
device object:
expected product:
follow-up action:
```

## Detection Engineering Notes

High-confidence detections often require joins:

```text
known vulnerable hash
  + load evidence
```

or:

```text
rare .sys write
  + service creation
  + suspicious controller process
  + security telemetry anomaly
```

Lower-confidence detections are still useful for inventory:

```text
rare signed driver
  + no business owner
  + broad device exposure
```

## Common Mistakes

- Treating `.sys` file creation as proof of driver load.
- Treating valid signatures as proof of safety.
- Ignoring legacy drivers already present before the investigation window.
- Relying only on filename without hash and signer.
- Assuming MDE sees every private driver interaction.
- Not validating ActionType values in the tenant schema.

## Study Questions

1. Why is BYOVD detection a correlation problem?
2. What is the difference between driver file presence and driver load?
3. Why should signer, hash, and path be reviewed together?
4. How can a telemetry gap become a signal after a driver load?
5. Why should server and workstation driver baselines be separated?

## References

- Microsoft Learn, Advanced Hunting schema tables:
  https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables
- Microsoft Learn, `DeviceFileEvents`:
  https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table
- Microsoft Learn, `DeviceProcessEvents`:
  https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table
- Microsoft Learn, `DeviceEvents`:
  https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table
- Microsoft Learn, `DeviceImageLoadEvents`:
  https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceimageloadevents-table
- Existing repo notes:
  `docs/detection-and-mitigation/byovd-hunting-and-hardening-checklists.md`,
  `docs/detection-and-mitigation/driver-load-etw-and-code-integrity.md`


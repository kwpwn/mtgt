# ThreatFire TfSysMon / SysMon.sys Deep Dive

Sources:

- BlackSnufkin TfSysMon-Killer source: `TfSysMon-Killer/src/main.rs`
- BlackSnufkin README: https://github.com/BlackSnufkin/BYOVD/tree/main/TfSysMon-Killer

`SysMon.sys` from ThreatFire System Monitor is another process-killer BYOVD. It is useful because the code shows a slightly different IOCTL buffer shape compared with BdApiUtil/K7.

## 1. Primitive

The primitive is:

```text
terminate process by PID through kernel driver
```

It does not expose arbitrary memory R/W in the public module.

## 2. DriverConfig Values

The public code defines:

```text
driver_name = SysMon
driver_file = sysmon.sys
device_path = \\.\TfSysMon
ioctl_code  = 0xB4A00404
```

Input buffer:

```text
24 bytes total
offset +0: 4 bytes padding
offset +4: PID as DWORD
offset +8: 16 bytes padding
```

This is useful because it shows not all process-kill drivers accept the same 4-byte PID shape.

## 3. Why the PID Is at Offset +4

The buffer shape likely reflects the vendor's internal request structure.

Possible layout:

- command field,
- PID field,
- flags/context,
- reserved bytes.

The PoC only knows what matters:

```text
driver reads PID from input + 4
```

Reverse engineering goal:

- identify minimal valid structure,
- fill unused fields with zero,
- keep buffer size expected by IOCTL handler.

## 4. Why This Uses byovd-lib

The module fits the generic process-killer abstraction:

- one driver,
- one device,
- one IOCTL,
- process name monitor,
- PID buffer builder.

The only custom logic is `build_ioctl_input()`.

This is exactly why `DriverConfig` exists.

## 5. ThreatFire vs BdApiUtil/K7

| Driver | Input format | Framework fit |
|---|---|---|
| BdApiUtil | 4-byte PID | trivial config |
| K7RKScan | 4-byte PID in standalone code | custom dual-mode logic |
| TfSysMon | 24-byte struct, PID at +4 | generic config with custom buffer |

The exploit class is the same, but protocol details differ.

## 6. Why This Is Listed on LOLDrivers but Still Useful

README notes the driver is listed on LOLDrivers but was absent from Microsoft recommended block rules at a point in time.

Lesson:

- LOLDrivers awareness does not automatically mean Windows blocks it.
- Microsoft blocklist coverage can lag.
- Local WDAC deny rules are still necessary.

## 7. BSOD/Stability

Same process-killer risk model:

- low risk for normal process target,
- medium risk for security process target,
- high risk for critical system process,
- medium risk on driver unload/old driver compatibility.

The 24-byte buffer reduces accidental malformed input risk because the PoC matches expected shape.

## 8. Defensive View

Hunt for:

- `sysmon.sys` ThreatFire driver hash from README,
- `\\.\TfSysMon` device access,
- old ThreatFire artifacts,
- driver load followed by security process termination,
- kernel service named `SysMon` that is not Microsoft Sysmon.

Important naming confusion:

- `SysMon.sys` here is ThreatFire, not Sysinternals Sysmon.
- Defenders should identify by hash/signer/path, not only name.

## 9. Final Takeaway

TfSysMon reinforces the process-killer pattern:

```text
old security driver + exposed terminate IOCTL + generic BYOVD framework
```

The technical value is in recognizing IOCTL buffer semantics and operationalizing the driver safely enough for repeatable process termination.


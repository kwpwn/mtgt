# BdApiUtil64.sys Process-Killer BYOVD Deep Dive

This document explains the Baidu `BdApiUtil64.sys` process-killer pattern in detail. It is based on the public `BdApiUtil-Killer` module and the shared `byovd-lib` framework from `BlackSnufkin/BYOVD`.

This driver fits the "small config, dangerous operation" category:

```text
driver-specific config
  -> shared BYOVD loader
  -> shared process monitor
  -> PID encoded into IOCTL buffer
  -> driver performs privileged process termination
```

The technical lesson is different from ASTRA64. The exploit value is not in complex kernel memory manipulation. It is in turning a powerful vendor driver operation into a reusable process-killer module.

## 1. What Primitive This Driver Gives

The practical primitive is:

```text
terminate process by PID from kernel context
```

The public module defines:

```text
driver_name  = BdApiUtil64
driver_file  = BdApiUtil64.sys
device_path  = \\.\BdApiUtil
ioctl_code   = 0x800024B4
input        = PID as 4 bytes
output_size  = 4
```

That is enough because the driver already implements the privileged operation internally.

## 2. Why the Per-Driver Code Is Tiny

`BdApiUtil-Killer/src/main.rs` only implements `DriverConfig`.

This is intentional. The exploit pattern is generic:

```text
load driver
open device
find target PID by name
send driver-specific IOCTL
repeat
cleanup
```

The only part that changes per driver is:

- service name,
- `.sys` filename,
- symbolic link/device path,
- IOCTL code,
- input buffer format,
- quirks such as unload behavior or error handling.

That is why this driver is a good example of BYOVD modularization.

## 3. The Role of `byovd-lib`

`byovd-lib` provides the common machinery:

- `ByovdDriver` for SCM install/start/stop/delete.
- `DeviceHandle` for `CreateFileW` and `DeviceIoControl`.
- process helpers to find PIDs by name.
- monitor loop to repeatedly kill matching processes.
- `DriverConfig` trait to define per-driver details.

The library turns one driver-specific module into a full BYOVD process killer.

This architecture mirrors real operator tooling: many vulnerable drivers, one common controller.

## 4. Why `DriverConfig` Is the Right Abstraction

The trait asks exactly the questions needed for a process-killer BYOVD:

```text
What service name?
What driver file?
What device path?
What IOCTL?
What input bytes?
What output size?
Any quirks?
```

This is better than hardcoding values throughout procedural code because:

- driver-specific values are auditable,
- new modules are easy to add,
- shared code is reused,
- behavioral detection metadata maps naturally to these fields.

Weakness:

- The abstraction can make dangerous drivers look deceptively simple.
- A four-line config may represent a kernel-privileged process killer.

## 5. Why PID Bytes Are Enough

`build_ioctl_input()` returns:

```text
pid.to_ne_bytes()
```

This means the driver expects a process identifier, not a complex request structure.

Why this is powerful:

- The driver does the privileged lookup/action.
- The user-mode exploit does not need process handles.
- It bypasses normal user-mode access checks if the driver does not validate the caller.

Why it is simple:

- PID is only 4 bytes.
- No pointer marshaling.
- No structure packing issues beyond endianness.

Why it is still fragile:

- PID can be stale.
- PID can be reused.
- Driver may behave badly if PID is invalid.
- Driver update can change input format.

## 6. Why Native Endian Is Acceptable Here

The module uses native-endian bytes. On Windows x64, this is little-endian.

That is acceptable because:

- target platform is Windows x64,
- driver and user-mode controller run on same machine architecture,
- PID is simple scalar data.

If this were a cross-platform protocol or on-disk/network format, native endian would be a bad design. For local Windows IOCTL input, it is usually acceptable.

## 7. Why Output Buffer Exists

The config sets output size to 4.

Possible reasons:

- Driver returns status/result code.
- IOCTL method expects output buffer even if caller does not care.
- The original vendor API uses in/out convention.

The exploit does not need the output for the core primitive. It needs the side effect: target process termination.

Important research point:

```text
IOCTL success/failure is not always the same as operation success/failure.
```

Some bad drivers perform the action but return an error. This is why the framework has `ignore_ioctl_error()`.

## 8. Why the Monitor Loop Exists

`run_monitor()` repeatedly:

- finds PIDs by process name,
- sends IOCTL for each PID,
- sleeps,
- repeats.

Why this is chosen:

- Security processes may restart.
- Target PID changes after restart.
- Operators care about keeping a class of processes down, not just one PID.

Trade-offs:

- Highly detectable.
- Can create service crash loops.
- Can destabilize the system.
- Can generate obvious event logs.

This is not stealth engineering. It is operational reliability engineering for process suppression.

## 9. Why Shared SCM Lifecycle Is Used

`ByovdDriver::install()` creates or opens a kernel-driver service. `start()` starts it. `stop_and_delete()` attempts cleanup.

Why this is good:

- Standard Windows mechanism.
- Reusable across drivers.
- Simple failure model.
- Works for signed drivers if policy allows.

Why it is noisy:

- Service Control Manager events.
- Kernel driver load telemetry.
- Driver path artifacts.
- Possible deletion-pending service artifacts.

For research tooling, SCM is the right default. For stealth, it is noisy.

## 10. Why Stop/Delete Is Optional in the Framework

Some drivers do not unload cleanly. The framework includes `skip_unload()`.

Why this matters:

- Old vendor drivers may not implement unload safely.
- Drivers may leave devices, callbacks, timers or worker threads active.
- Stopping them can crash the system.

For a process-killer BYOVD, unloading is not part of exploitation; it is cleanup. If cleanup is riskier than leaving it loaded in a lab, skipping unload can be justified.

Defensively, failed unload or delete-pending service can be a useful artifact.

## 11. Why This Driver Fits a Generic Process-Killer Framework

It has:

- one target identifier,
- one IOCTL,
- simple input,
- process termination side effect.

It does not require:

- multi-stage setup,
- physical mapping,
- kernel address discovery,
- offsets,
- symbols,
- target object validation.

That is why `DriverConfig` is enough.

If a driver required physical memory R/W or complex auth crypto, this simple trait would not be enough.

## 12. Process-Killer vs Memory-R/W BYOVD

| Dimension | BdApiUtil-style process killer | ASTRA-style physical R/W |
|---|---|---|
| Primitive | High-level process termination | Low-level physical memory access |
| OS internals needed | Minimal | Extensive |
| Version sensitivity | Driver protocol/policy | Driver + Windows structure offsets |
| BSOD risk | Lower | Higher |
| Generality | Narrow | Broad |
| Operational value | EDR/AV kill | LPE/general kernel object manipulation |
| Mitigation focus | WDAC/blocklist/access control | WDAC + memory protections + validation |

Neither is strictly "better". They solve different problems.

## 13. Why This Can Bypass User-Mode Security Boundaries

Normal user mode must pass:

- process DACL checks,
- privilege checks,
- PPL restrictions,
- security product self-defense.

The vulnerable driver may bypass these because:

- it runs in kernel mode,
- it can reference process objects directly,
- it can call termination routines with kernel privileges,
- it may not check who requested the action.

The key failure is not memory corruption. It is missing authorization on a dangerous feature.

## 14. Why This Is a Confused Deputy

A confused deputy occurs when a privileged component performs an action for an untrusted caller without verifying that the caller is allowed.

Here:

```text
caller: untrusted process
deputy: signed Baidu kernel driver
action: terminate target process
```

The driver has authority. The caller does not. The bug is that the caller can direct the driver's authority.

This mental model is useful for many BYOVD cases:

- arbitrary file delete,
- process kill,
- protected memory read,
- registry modification,
- callback unregister.

## 15. Stability Across Windows Versions

The exploit controller uses stable APIs:

- SCM APIs,
- `CreateFileW`,
- `DeviceIoControl`,
- process enumeration.

Those APIs are stable.

The driver itself may not be:

- may be blocklisted,
- may fail under HVCI,
- may not load on newer Windows,
- may have fixed IOCTL handling,
- may have different device path.

Thus:

```text
controller stability is high
driver availability is the limiting factor
```

## 16. Stability Across Driver Versions

The following can break the module:

- IOCTL code changes.
- input changes from PID to structure.
- device path changes.
- service name changes.
- required caller access changes.
- driver adds signer/process validation.
- driver blocks protected process targets.

This is why BYOVD catalogs need hash/version tracking, not just driver name.

## 17. BSOD Risk Model

Process-killer drivers are usually less crash-prone than arbitrary-write drivers, but there are still risks.

| Stage | Risk | Reason |
|---|---|---|
| SCM create | Low | Fails cleanly if denied. |
| Driver start | Low-medium | Old driver compatibility issues. |
| Device open | Low | Fails cleanly. |
| IOCTL with valid PID | Low | Intended operation. |
| IOCTL with invalid PID | Low-medium | Depends on driver validation. |
| Kill user process | Low | Normal termination. |
| Kill AV/EDR process | Medium | Self-defense/watchdogs may react. |
| Kill critical Windows process | High | Can reboot/hang/crash host. |
| Cleanup/unload | Medium | Old drivers may unload poorly. |

The exploit avoids direct kernel memory corruption, so BSOD risk mostly comes from driver quality and target selection.

## 18. Why HVCI/SMEP/kCFG Do Not Matter Much Here

This technique does not:

- execute user shellcode in kernel,
- patch kernel code,
- hijack indirect calls,
- allocate W+X memory,
- corrupt page tables.

Therefore:

- SMEP is mostly irrelevant.
- NX is mostly irrelevant.
- kCFG/CET are mostly irrelevant.
- HVCI code integrity is only relevant to whether the driver is allowed to load and execute.

The real mitigations are:

- driver blocklist,
- WDAC,
- correct driver ACL,
- caller validation,
- product update.

## 19. What Good Driver Design Would Do

A secure driver with process termination capability should:

- create device object with restrictive SDDL,
- require admin/SYSTEM or trusted service caller,
- validate caller identity,
- validate target process class,
- deny termination of protected/security-critical processes unless explicitly authorized,
- avoid exposing raw kill IOCTLs directly to arbitrary user mode,
- broker operations through a signed service with policy checks,
- log privileged operations.

If any local user can open the device and send a PID, the design is broken.

## 20. Why Hash/Signer-Based Blocking Matters

Driver name alone is weak:

- files can be renamed,
- services can use arbitrary names,
- drivers can be copied to staging directories.

Better identifiers:

- SHA256 hash,
- certificate signer,
- version resource,
- PE timestamp,
- device object name,
- IOCTL behavior,
- imports and code patterns.

For BdApiUtil-style drivers, behavior-based detection should focus on:

```text
kernel driver load + process kill effect
```

rather than only exact filename.

## 21. How to Validate Impact Safely in a Lab

Safer testing targets:

- a disposable notepad process,
- a test process running under same user,
- a controlled service in a VM snapshot.

Avoid:

- `csrss.exe`,
- `wininit.exe`,
- `lsass.exe` on non-disposable systems,
- EDR/AV in production,
- kernel-critical services.

Validation:

- confirm process existed before IOCTL,
- send IOCTL,
- confirm process exit,
- collect driver load and service events,
- reboot VM from snapshot if needed.

This keeps the research focused on primitive behavior without unnecessary system damage.

## 22. Why This Is Operationally Dangerous Despite Being Simple

The simplicity is the danger:

- No offsets.
- No KASLR.
- No ROP.
- No shellcode.
- No exploit reliability tuning.

An operator can add a new process-killer driver to a framework with a few constants.

That scales better than complex memory exploitation.

For defenders, the response must also scale:

- app control,
- driver inventory,
- blocklists,
- detection correlation,
- removal of obsolete vendor drivers.

## 23. Reliability Improvements for This Module

A stronger research implementation would:

- verify driver hash before loading,
- verify signer and version,
- check if driver already loaded from unexpected path,
- add one-shot mode,
- add dry-run mode,
- verify process exit,
- log target executable path and SID,
- refuse critical system process names by default,
- add timeout and backoff to monitor loop,
- expose exact Win32 error codes,
- record telemetry useful for detections.

These improvements do not change exploitability; they improve repeatability and safety.

## 24. Final Takeaway

BdApiUtil64-style BYOVD is about abstraction:

```text
dangerous driver capability + generic loader/monitor framework = reusable process killer
```

The important question is not:

```text
Can I get arbitrary kernel R/W?
```

The important question is:

```text
Does this signed driver expose a privileged operation I can direct at a target?
```

If yes, the exploit can be short, stable across OS builds, and still operationally severe.


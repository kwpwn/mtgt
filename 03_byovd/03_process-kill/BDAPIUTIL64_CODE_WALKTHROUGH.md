# BdApiUtil-Killer / BdApiUtil64.sys Code Walkthrough

Source code analyzed:

- `BdApiUtil-Killer/src/main.rs`
- `byovd-lib/src/lib.rs`
- `byovd-lib/src/device.rs`
- `byovd-lib/src/service.rs`

Upstream: https://github.com/BlackSnufkin/BYOVD/tree/main/BdApiUtil-Killer

## Driver Role

`BdApiUtil64.sys` is modeled as another process-killer BYOVD driver. The per-driver module is intentionally tiny because the shared `byovd-lib` handles the common lifecycle and IOCTL dispatch.

The exploit does not construct a kernel memory primitive. It invokes a privileged operation exposed by the driver.

## Why This Module Is Small

`BdApiUtil-Killer/src/main.rs` defines a `BdApiUtilDriver` struct and implements `DriverConfig`.

The driver-specific details are:

- Service name.
- Driver filename.
- Device path.
- IOCTL code.
- Input buffer format.
- Output buffer size.

Everything else is delegated to `byovd-lib::run()`.

This is a deliberate architecture choice: many process-killer BYOVD drivers have the same controller flow and differ only in driver metadata and IOCTL buffer format.

## Shared Library Flow

`byovd-lib::run()` performs the full generic BYOVD flow:

1. Run optional preflight checks.
2. Install/register the driver service.
3. Start the service.
4. Monitor for target process name.
5. Send the configured IOCTL for each matching PID.
6. Stop and delete the service unless configured otherwise.

The library abstracts away:

- Service Control Manager interaction.
- Device opening.
- `DeviceIoControl` dispatch.
- Process name monitoring.
- Cleanup.

## DriverConfig Design

`DriverConfig` is the key abstraction.

It asks each driver module:

- What is the service name?
- What `.sys` file should be staged?
- What device path should be opened?
- What IOCTL should be sent?
- What bytes should be sent for a target PID/process?
- Does the driver need special access flags?
- Should unload be skipped?
- Should IOCTL errors be ignored?

This is why `BdApiUtil-Killer` is concise: it only supplies answers to those questions.

## Why `build_ioctl_input()` Returns the PID Bytes

For `BdApiUtil64.sys`, the input buffer is just the target PID encoded as native-endian bytes.

That tells us the vulnerable driver operation is high-level. The driver is expected to:

- Receive a process identifier.
- Resolve the process internally.
- Perform the privileged termination operation in kernel context.

The exploit does not need to pass pointers, lengths, fake objects or shellcode because the driver already contains the privileged behavior.

## Why the Shared Library Uses a Monitor Loop

`run_monitor()` continuously scans for a process name and calls `send_ioctl()` for each matching PID.

This is useful for process-killer BYOVD because:

- Security tools may restart after termination.
- PID values change after restart.
- Operators often care about names such as AV/EDR agent processes, not one static PID.

The monitor loop makes the primitive persistent at the user-mode controller layer without needing persistent kernel tampering.

## DeviceHandle IOCTL Layer

`DeviceHandle` wraps:

- `CreateFileW` for opening the driver device.
- `DeviceIoControl` for typed, raw and byte-slice IOCTL dispatch.

For this module, `send_ioctl()` uses `ioctl_bytes_legacy()`:

- Build input bytes through `DriverConfig`.
- Allocate optional output buffer.
- Send IOCTL.
- Enforce or ignore success depending on driver config.

The "legacy" naming reflects that many old drivers return odd status values even when they perform the operation. The abstraction supports those differences.

## Service Lifecycle Layer

`ByovdDriver::install()`:

- Opens the Service Control Manager.
- Opens an existing service if present.
- Otherwise creates a kernel-driver service.
- Resolves the driver path from current directory unless an override is provided.

`start()`:

- Starts the service.
- Treats "already running" as success.

`stop_and_delete()`:

- Attempts to stop the driver.
- Marks the service for deletion.

This matches normal BYOVD staging. The exploit assumes the attacker has enough privilege to load a signed driver unless the target system already has it loaded.

## Why Process-Kill BYOVD Uses This Architecture

For memory-R/W drivers, every exploit chain is different: page tables, offsets, symbol discovery, HVCI behavior and payload vary.

For process-killer drivers, the flow is generic:

1. Load driver.
2. Open device.
3. Find target PID.
4. Send driver-specific kill request.
5. Repeat as needed.

That generic flow is exactly what `byovd-lib` implements.

## Why This Technique Was Chosen

`BdApiUtil64.sys` exposes a direct process termination primitive. There is no reason for the PoC to build arbitrary kernel R/W if the intended impact is killing a process.

The cleanest exploit engineering choice is to isolate driver-specific values in `DriverConfig` and reuse the shared process-killer framework.

## Main Failure Points

- The driver is blocklisted or WDAC-denied.
- The driver file is not present beside the controller or at the supplied path.
- The service cannot be created or started.
- The device path differs from the expected one.
- The target process name is wrong or the process restarts.
- The driver returns failure even if it acted, requiring `ignore_ioctl_error()` style handling for some modules.

## Defensive Takeaways

- Generic BYOVD frameworks make adding new process-killer drivers cheap.
- Defenders should detect the common lifecycle, not only one driver:
  - kernel service creation,
  - driver load,
  - device open,
  - repeated target process enumeration,
  - security process termination.
- Driver-specific IOCTL telemetry is valuable but rarely available everywhere.
- WDAC deny rules should cover obsolete security-product drivers even if they are signed.

## Engineering Decision Analysis

BdApiUtil-Killer is mostly an abstraction exercise. The interesting engineering is not a custom memory exploitation chain; it is how the repo turns many process-killer drivers into small configuration modules.

### Decision 1: Use `byovd-lib` instead of standalone code

Chosen path:

- Implement `DriverConfig`.
- Delegate lifecycle and IOCTL dispatch to `byovd-lib::run()`.

Alternative:

- Write a standalone controller like `K7Terminator`.

Why the chosen path is better:

- The driver fits a generic pattern: load driver, open device, send target PID, repeat.
- Shared lifecycle code reduces copy/paste bugs.
- Adding new process-killer drivers becomes cheap.
- It makes driver-specific differences obvious: service name, device path, IOCTL, buffer format.

Why standalone might be better for some drivers:

- Drivers with unusual buffering, multi-stage handshakes, timing races or multiple IOCTLs may need custom flow.
- Memory-R/W drivers like Astra64 need custom logic and do not fit this abstraction.

Stability:

- High for process-killer drivers with simple PID input.
- Low for drivers needing complex state or unusual return behavior unless trait hooks are extended.

BSOD risk:

- Lower than custom memory exploitation.
- Mostly tied to what target process is killed and driver compatibility.

### Decision 2: Encode only driver metadata in `DriverConfig`

Chosen path:

- `driver_name()`
- `driver_file()`
- `device_path()`
- `ioctl_code()`
- `build_ioctl_input()`
- `ioctl_output_size()`

Alternative:

- Hardcode values throughout a procedural exploit.

Why the chosen path is better:

- It separates exploit framework from driver specifics.
- It is easier to audit: all dangerous driver constants are in one place.
- It supports a catalog of similar drivers.
- It makes detection mapping easier because the same fields are exactly what defenders care about.

Weakness:

- It can hide how dangerous the operation is. A tiny config file may still represent a powerful kernel primitive.
- It assumes the driver operation is one IOCTL per target.

Stability:

- Stable as long as the driver protocol is simple.
- Breaks if vendor changes input structure, device name or service behavior.

BSOD risk:

- None from abstraction itself.

### Decision 3: Use PID bytes as the input buffer

Chosen path:

- `build_ioctl_input()` returns the target PID as four native-endian bytes.

Alternative:

- Pass process name.
- Pass a structured request.
- Open a user-mode process handle and pass handle.

Why PID is likely chosen:

- The vulnerable driver API expects PID.
- PID is enough for a kernel driver to resolve `EPROCESS` or call a terminate routine.
- PID buffers are simple and make the PoC minimal.

Why not process name:

- Kernel drivers generally operate on process objects or PIDs, not executable names.
- Name matching is better done in user mode, where Toolhelp/process APIs are available.

Why not handle:

- A user-mode handle would reintroduce access checks.
- PID lets the driver perform privileged lookup internally, which is exactly the authorization issue.

Stability:

- PID size and semantics are stable.
- Native endian is fine on Windows x64 little-endian.
- Driver-specific expectation can still change.

BSOD risk:

- Low for valid PIDs.
- Medium if the driver mishandles stale or invalid PIDs.

### Decision 4: Use monitor loop instead of one-shot termination

Chosen path:

- Continuously monitor a process name and send IOCTL for matching PIDs.

Alternative:

- Resolve once, kill once, exit.

Why monitor loop is used:

- Security agents often restart.
- PIDs change after restart.
- The BYOVD value is often to keep a target suppressed long enough for another operation.

Trade-off:

- Much noisier.
- Easier to detect with correlation.
- Can destabilize machines if target process is critical or supervised aggressively.

Stability:

- Good for simple restart loops.
- Poor against products that block the driver after first detection or unload it.

BSOD risk:

- Low to medium. Repeated termination of security components can trigger watchdog or recovery behavior.

### Decision 5: Use SCM install/start/cleanup in the shared library

Chosen path:

- `ByovdDriver::install()`
- `start()`
- `stop_and_delete()`

Alternative:

- Require the driver to already be loaded.
- Use `NtLoadDriver` manually.
- Leave service installed.

Why this path is chosen:

- It is reproducible and generic.
- It mirrors real BYOVD staging.
- Cleanup reduces leftover artifacts in lab.
- SCM APIs produce predictable errors and work across Windows versions.

Weakness:

- Requires administrative rights or equivalent.
- Generates obvious service-control telemetry.
- Blocklist/WDAC can prevent loading.

Stability:

- High when policy allows the driver.
- Driver unload can be unstable for some old drivers, hence the trait has `skip_unload()`.

BSOD risk:

- Driver start: low to medium.
- Driver stop/unload: medium for poor-quality drivers.
- The library's `skip_unload()` hook exists because some drivers crash on unload.

### Decision 6: Provide `ignore_ioctl_error()`

Chosen path:

- The framework can ignore failed IOCTL return status for drivers that act but report failure.

Alternative:

- Treat every failed `DeviceIoControl` as failure.

Why this exists:

- Many vendor drivers return inconsistent NTSTATUS/Win32 status.
- Some perform the privileged action before returning an error.
- PoC frameworks need to tolerate bad driver API hygiene.

Risk:

- Ignoring errors can hide real failures.
- It can make the tool report success when nothing happened unless the effect is independently verified.

Stability:

- Useful across messy legacy drivers.
- Should be driver-specific, not default.

BSOD risk:

- None directly.

### Version Stability Summary

| Component | Stability | Reason |
|---|---|---|
| `DriverConfig` abstraction | High | User-mode framework design. |
| SCM lifecycle | High | Standard Windows service model. |
| Device path | Driver-version dependent | Vendor-controlled symbolic link. |
| IOCTL code | Driver-version dependent | Vendor-controlled dispatch table. |
| PID input format | Medium-high | Simple, but still driver-specific. |
| Process monitor loop | High | User-mode API behavior is stable. |
| Driver unload cleanup | Low-medium | Old drivers often have unsafe unload paths. |

### BSOD Risk Summary

| Stage | Risk | Reason |
|---|---|---|
| Framework setup | None | User-mode only. |
| Service creation | None-low | Usually returns error if blocked. |
| Driver start | Low-medium | Old/blocked/incompatible driver can crash or fail. |
| Device open | None | Handle open failure only. |
| Kill IOCTL | Low-medium | Depends on target and driver PID handling. |
| Monitor loop | Medium | Repeated security process termination can destabilize host. |
| Driver stop/unload | Medium | Some vulnerable drivers do not unload cleanly. |

### Why This Technique Is Good

This design is good for cataloging many BYOVD process-kill drivers:

- Small per-driver modules.
- Consistent execution flow.
- Easy to compare IOCTLs and device names.
- Easy to add detection metadata.
- No need for kernel offsets or mitigation-specific bypasses.

It is not good for:

- Arbitrary memory primitives.
- Drivers requiring multiple setup IOCTLs.
- Exploits that depend on exact OS internals.
- Cases where the final impact is LPE rather than process termination.

### Reliability Improvements Worth Considering

- Add driver hash/version validation before loading.
- Add an optional one-shot mode in addition to monitor mode.
- Verify target process actually exited after IOCTL.
- Add allow/deny target safety list.
- Record SCM, device-open and IOCTL errors with exact Win32 codes.
- Add `skip_unload()` for drivers known to crash on unload.
- Store detection metadata beside `DriverConfig`: signer, known hashes, LOLDrivers ID, blocklist status.

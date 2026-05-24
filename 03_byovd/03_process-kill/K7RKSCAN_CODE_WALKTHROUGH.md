# K7Terminator / K7RKScan.sys Code Walkthrough

Source code analyzed:

- `K7Terminator/src/main.rs`

Upstream:

- https://github.com/BlackSnufkin/BYOVD/tree/main/K7Terminator
- https://blacksnufkin.github.io/posts/BYOVD-CVE-2025-52915/

## Driver Role

`K7RKScan.sys` is treated as a privileged process-termination driver. The exploit does not build arbitrary kernel read/write and does not try to execute kernel shellcode. It abuses an existing privileged function the security product driver already exposes.

This is an important BYOVD category: the driver itself is the weapon. If it will terminate protected or security processes for an untrusted caller, full arbitrary memory access is unnecessary.

## Code Structure

The whole PoC is in `main.rs`.

Important constants:

- Driver service name.
- Driver device path.
- Process-kill IOCTL.
- Desired access used when opening the device.

Important structs:

- `Config`: mode, target PID, target process names, looping behavior, optional driver path.
- `K7Terminator`: wrapper that executes service handling, process discovery and IOCTL dispatch.

Important methods:

- `is_service_running()`
- `load_driver()`
- `get_pids_by_name()`
- `kill_process()`
- `execute()`
- `terminate_pid()`
- `terminate_name()`

## Why There Are Two Modes

The code supports:

- BYOVD mode: load the driver itself through the Service Control Manager.
- LPE mode: wait until the legitimate K7 service loads the driver, then race or use the exposed device.

This matches the vulnerability story:

- Older versions had weaker access behavior that made low-privileged use possible.
- Newer/current versions may require a BYOVD-style admin/post-exploitation context, but still expose the dangerous operation once loaded.

The code's `mode` boolean controls this. In BYOVD mode, `execute()` calls `load_driver()`. In LPE mode, it loops until `is_service_running()` reports that the K7 service exists and is running.

## Why SCM Loading Is Used in BYOVD Mode

`load_driver()` uses the Service Control Manager to create/open a kernel-driver service and start it.

This is the standard BYOVD lifecycle:

1. Provide a signed vulnerable `.sys`.
2. Register it as a kernel driver service.
3. Start it.
4. Open its device object.
5. Send the vulnerable IOCTL.

The code resolves relative driver paths to the current directory because BYOVD tooling commonly stages the driver beside the controller executable.

## Why LPE Mode Waits for Service Readiness

In LPE mode the code does not load the driver. It waits for K7's legitimate service to load it.

This is used when the vulnerability is reachable during normal product operation. Instead of requiring driver-load privileges, the attacker waits for an existing privileged service to create the vulnerable kernel device.

The retry loop in `kill_process()` exists because the service and device object may not be ready at exactly the same time. This is a timing issue, not an exploit primitive by itself.

## Process Discovery Logic

`get_pids_by_name()` uses Toolhelp snapshots:

- Create process snapshot.
- Iterate `PROCESSENTRY32`.
- Compare image names case-insensitively.
- Return every matching PID.

This is used because process-killer BYOVD attacks often target security products by process name rather than a single stable PID. PIDs change across restarts, but process names such as AV/EDR services are predictable.

## IOCTL Dispatch Logic

`kill_process(pid)` opens the driver device and sends the target PID as the input buffer for the kill IOCTL.

Why the buffer is simple:

- The vulnerable operation exposed by the driver is already high level.
- The driver likely resolves the PID internally and performs termination in kernel context.
- The user-mode PoC only needs to pass the target identifier.

This is very different from Astra64-RW. There is no need for page-table walking, token offsets, kernel base discovery or PE parsing because the driver already implements the privileged action.

## Why Process Termination Is the Chosen Technique

Because the driver gives a process-termination primitive, the most direct impact is defense evasion:

- Terminate AV/EDR.
- Terminate PPL or protected service processes if the driver does not enforce caller authorization correctly.
- Loop and repeatedly kill a process if a watchdog restarts it.

The code's `looper` option exists for that operational reason: security services often restart. A single kill may not be enough.

## Why This Can Bypass PPL

PPL restricts normal user-mode handles and termination. A kernel driver is not bound by the same user-mode access checks if it performs termination itself.

If `K7RKScan.sys` accepts the request, the termination happens with kernel privileges. The user-mode caller does not need `PROCESS_TERMINATE` access to the protected process.

## Main Failure Points

- The target driver version is not vulnerable.
- The driver device path is different.
- The service fails to load due to blocklist/WDAC/HVCI policy.
- The caller lacks SCM privileges in BYOVD mode.
- In LPE mode, the legitimate service never loads the vulnerable device.
- The target process restarts faster than the loop can kill it.

## Why This Technique Was Chosen

The driver does not need to be converted into arbitrary kernel memory access. It already provides a privileged process-control operation. The shortest path to impact is therefore:

1. Ensure the vulnerable driver is loaded.
2. Find target PID(s).
3. Send PID through the driver's process-kill IOCTL.
4. Repeat if the process is supervised.

This is why the implementation is small. The exploit is not technically shallow; the vulnerability is simply a high-level authorization failure rather than a memory primitive.

## Defensive Takeaways

- Detect driver loads on hosts not running K7.
- Detect process-kill attempts against security processes immediately after driver load.
- Treat process-killer drivers as high priority even if they do not expose arbitrary R/W.
- Block old signed K7 driver versions with WDAC.
- Watch for looping behavior where the same security process is killed repeatedly.

## Engineering Decision Analysis

K7Terminator is a different class from Astra64-RW. It is not trying to manufacture a memory primitive. It takes a high-level privileged operation exposed by the driver and makes it usable against arbitrary target processes.

### Decision 1: Use the driver's process-kill IOCTL instead of arbitrary kernel R/W

Chosen path:

- Open the K7 driver device.
- Send a target PID to the process-kill IOCTL.

Alternative:

- Reverse more driver internals to find arbitrary read/write.
- Chain another driver for memory R/W.
- Use user-mode `OpenProcess` / `TerminateProcess`.

Why the chosen path is better:

- It matches the primitive the driver already exposes.
- It is smaller and more reliable than building a memory-corruption chain.
- It avoids offsets, KASLR, page tables, PatchGuard and token structure changes.
- It directly achieves the operational goal: terminate security processes.

Why user-mode process termination is not enough:

- PPL and process DACLs can block normal termination.
- Security products protect their processes from normal user-mode handles.
- Kernel driver termination happens above that boundary if the driver accepts the request.

Stability:

- High across OS versions if the vulnerable driver version and IOCTL semantics stay the same.
- Low across driver versions if K7 changes device name, IOCTL code, access control or input format.

BSOD risk:

- Low compared with memory R/W exploits.
- Risk increases if the driver mishandles invalid PIDs, races target process exit, or terminates critical system processes.

### Decision 2: Support both BYOVD mode and LPE mode

Chosen path:

- BYOVD mode loads the driver using SCM.
- LPE mode waits for an existing K7 service/driver to become available.

Alternative:

- Only support BYOVD mode.
- Only support low-privileged LPE mode.

Why both modes are useful:

- The exploitability model changed across versions.
- If the system already has the vulnerable K7 product installed, waiting for its service avoids needing to load a driver.
- If the product is not installed, a post-exploitation attacker with driver-load capability can bring the vulnerable signed driver.

Trade-off:

- BYOVD mode requires higher privilege to create/start a kernel driver service.
- LPE mode depends on product presence and timing.

Stability:

- BYOVD mode is stable when driver load is allowed.
- LPE mode is environment-dependent and can fail if service lifecycle changes.

BSOD risk:

- BYOVD load risk is usually low, but old security drivers can be unstable on newer Windows builds.
- LPE mode adds little kernel risk beyond using the IOCTL.

### Decision 3: Use SCM loading instead of a custom driver loader

Chosen path:

- Use `OpenSCManagerW`, `CreateServiceW`, `StartServiceW`.

Alternative:

- Use `NtLoadDriver` directly.
- Abuse an existing vulnerable loader.
- Manual-map a driver.

Why SCM is chosen:

- It is the normal Windows mechanism for kernel service loading.
- It is straightforward and reliable.
- It produces predictable service-control telemetry, which is fine for a PoC.
- It avoids additional loader complexity that would obscure the driver vulnerability.

Why not manual-map:

- HVCI/DSE and kernel integrity make unsigned or manually mapped driver code impractical.
- The whole BYOVD point is to use a legitimately signed driver.

Stability:

- High on Windows when caller has rights and policy allows the driver.
- Blocklist/WDAC can prevent start.

BSOD risk:

- Low unless the driver itself is incompatible with the OS version.

### Decision 4: Target by process name as well as PID

Chosen path:

- Support `--pid`.
- Support one or more `--name` values.
- Resolve names to PIDs repeatedly.

Alternative:

- Require only PID.
- Hardcode security product process names.

Why name targeting is chosen:

- AV/EDR PIDs are not stable.
- Security services can restart under a new PID.
- Process names are the natural operator input for process-killer tooling.

Why keep PID support:

- It is useful for testing a specific process.
- It avoids ambiguity when multiple processes share a name.
- It maps directly to the driver's IOCTL input.

Stability:

- Name enumeration is stable as a user-mode technique.
- It can miss protected or rapidly respawning processes depending on timing.

BSOD risk:

- None from enumeration.
- Terminating the wrong critical PID can crash or destabilize the system.

### Decision 5: Add `looper`

Chosen path:

- Keep scanning and killing target processes when `--looper` is set.

Alternative:

- Send one IOCTL and exit.

Why looping is useful:

- Security agents often have watchdogs.
- Service Control Manager may restart services.
- A single termination does not guarantee defense evasion.

Why it is risky:

- It is very noisy.
- It can create a clear detection pattern: repeated process death after driver load.
- It can destabilize the host if it kills critical dependencies repeatedly.

Stability:

- Operationally effective against simple restart loops.
- Less effective if the security product unloads/blocks the driver or protects itself at boot.

BSOD risk:

- Low from loop mechanics.
- Medium if repeatedly killing kernel-adjacent security service processes triggers watchdog bugs or system recovery.

### Decision 6: Open device with write access only

Chosen path:

- Use `GENERIC_WRITE` for the device handle.

Alternative:

- Request read/write/all access.

Why this is reasonable:

- The operation is command-style: send PID, ask driver to terminate.
- Requesting less access can avoid unnecessary open failures if the device ACL distinguishes access masks.
- It documents the primitive: the caller needs command/write capability, not readback.

Stability:

- Depends on driver device ACL and required access bits.
- If the driver checks access more strictly in later versions, the open can fail.

BSOD risk:

- None.

### Decision 7: Retry device opening in LPE mode

Chosen path:

- In LPE mode, loop until the device is openable.

Alternative:

- Fail immediately if `CreateFileW` fails.

Why retry is needed:

- Service running does not guarantee the device object is ready.
- Driver initialization and symbolic link creation can lag service status.
- Race windows are common in service/driver startup.

Stability:

- Improves reliability against timing issues.
- Can hang forever if the service is running but the device is never exposed.

BSOD risk:

- None from retry.

### Version Stability Summary

| Component | Stability | Reason |
|---|---|---|
| SCM loading | High | Standard Windows driver loading path. |
| Device path | Driver-version dependent | Vendor can rename symbolic link. |
| IOCTL code | Driver-version dependent | Any driver update can change dispatch. |
| PID input format | Medium | Simple formats often stay stable but are not guaranteed. |
| Process enumeration | High | Standard Toolhelp APIs. |
| PPL bypass effect | Depends on driver behavior | If driver enforces authorization, impact disappears. |
| Looper behavior | High | User-mode controller logic. |

### BSOD Risk Summary

| Stage | Risk | Reason |
|---|---|---|
| Driver load | Low-medium | Old driver may be incompatible or blocked. |
| Device open | None-low | Failure returns handle error. |
| PID enumeration | None | User-mode only. |
| Kill IOCTL on normal process | Low | Driver performs intended operation. |
| Kill IOCTL on protected/security process | Low-medium | Product/kernel dependencies may react unexpectedly. |
| Kill IOCTL on critical system process | High | Can trigger system instability or reboot. |
| Looper mode | Medium | Repeated disruption increases operational risk. |

### Why This Is Still High-Value Without Kernel R/W

Process-kill BYOVD is less technically general than arbitrary R/W, but it is often more operationally reliable:

- No offsets.
- No KASLR bypass.
- No PatchGuard-sensitive structure corruption.
- No shellcode.
- No page-table translation.
- Directly targets AV/EDR disruption.

The trade-off is that it cannot do arbitrary kernel post-exploitation. It is a narrow tool: powerful for defense evasion, weak for general research primitives.

### Reliability Improvements Worth Considering

- Add timeout for LPE wait loops.
- Verify driver version/hash before use.
- Add denylist of critical Windows processes to avoid accidental system crash in lab.
- Log exact `GetLastError()` for every failed open/start/IOCTL.
- Add target process revalidation immediately before IOCTL.
- Add a dry-run mode that enumerates target PIDs without sending IOCTL.

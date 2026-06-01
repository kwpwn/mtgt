# K7RKScan.sys Process-Killer BYOVD Deep Dive

This document explains the K7Terminator technique concept by concept. It is based on the public `K7Terminator/src/main.rs` code from `BlackSnufkin/BYOVD` and the public write-up for CVE-2025-52915 / CVE-2025-1055.

Unlike ASTRA64, this is not a physical-memory R/W exploit. It is a high-level privileged-operation abuse case:

```text
load or wait for K7RKScan.sys
  -> open exposed device
  -> resolve target PID(s)
  -> send process-kill IOCTL
  -> driver terminates process in kernel context
```

The important lesson: not every dangerous BYOVD gives arbitrary read/write. Some drivers expose exactly the operation an attacker wants.

## 1. What Primitive This Driver Gives

The primitive is not:

- arbitrary kernel read,
- arbitrary kernel write,
- MSR access,
- physical memory mapping,
- kernel code execution.

The primitive is:

```text
kernel-privileged process termination by PID
```

That means user mode can ask the signed driver to terminate a target process, and the driver performs the privileged action from kernel mode.

Why this is powerful:

- User-mode `TerminateProcess` can be blocked by DACLs, PPL, protected handles or security product self-defense.
- Kernel drivers can act above those user-mode restrictions.
- If the driver does not enforce caller authorization, a weak user-mode caller can indirectly perform a kernel-privileged kill.

## 2. Why This Is Still BYOVD Without R/W

Many people mentally equate BYOVD with arbitrary kernel memory R/W. That is too narrow.

BYOVD means:

```text
bring a signed vulnerable driver to perform privileged actions
```

The privileged action can be:

- physical memory R/W,
- virtual memory R/W,
- MSR access,
- process kill,
- callback tamper,
- file delete,
- registry modification,
- protected object access.

For ransomware and EDR bypass, process-kill is often enough.

The driver does not need to be universal. It only needs to solve a specific attacker problem.

## 3. The K7Terminator Code Shape

The public code is compact because the driver already provides the high-level operation.

Core constants:

```text
DRIVER_NAME   = K7RKScan
DRIVER_DEVICE = \\.\DosK7RKScnDrv
IOCTL_KILL    = 0x222018
```

Core flow:

```text
parse CLI
choose mode: lpe or byovd
if byovd:
    create/start kernel driver service
else:
    wait for existing K7 service
resolve target PID(s)
open device
send PID to IOCTL_KILL
optionally loop
```

This is why the code has no PE parsing, no CR3, no offsets, no page tables.

The vulnerability is at the authorization/operation boundary, not at the memory primitive boundary.

## 4. Why Two Modes Exist: LPE vs BYOVD

The tool supports:

```text
-m lpe
-m byovd
```

These modes model two different exploitation situations.

LPE mode:

- The vulnerable K7 product/driver is already installed.
- The tool waits until the legitimate service loads the driver.
- The attacker does not necessarily need to load a driver.
- The vulnerability behaves more like local privilege escalation or authorization bypass.

BYOVD mode:

- The attacker supplies the vulnerable signed driver.
- The tool registers and starts it using SCM.
- This requires driver-load capability, usually administrative or equivalent.
- The driver becomes a post-exploitation defense-evasion tool.

Why support both:

- Driver vulnerabilities evolve. One version may be reachable by low-priv users; another may require admin but still be abusable once loaded.
- Real systems differ: some have K7 installed, some do not.
- The same vulnerable driver can be useful in both "already present" and "bring your own" models.

## 5. Why Process-Kill Is Chosen Instead of Hunting R/W

Alternative path:

```text
reverse driver deeply
find arbitrary R/W
build token swap or code-exec chain
```

Chosen path:

```text
use exposed process-kill IOCTL
```

Why the chosen path is better:

- It directly matches the driver feature.
- It avoids kernel offsets.
- It avoids BSOD-prone memory corruption.
- It avoids mitigation problems like HVCI/kCFG/CET.
- It achieves the likely operational goal: kill protected/security processes.

When this is enough:

- EDR/AV disablement.
- Ransomware pre-stage.
- Killing backup agents.
- Killing monitoring/logging agents.
- Denial of service against protected security services.

When it is not enough:

- You need SYSTEM shell.
- You need arbitrary file/memory modification.
- You need persistence.
- You need stealthy kernel tamper.

This technique is narrow but practical.

## 6. Why It Can Affect PPL/Security Processes

PPL protects processes from normal user-mode access. A normal process cannot simply open a PPL process with termination rights.

But a kernel driver can terminate a process if it calls the right kernel routines or uses equivalent privileged object access internally.

The bypass condition is:

```text
untrusted caller can cause trusted kernel driver to terminate chosen PID
```

PPL is not bypassed because the caller got a better handle. It is bypassed because the caller delegates the action to a kernel component.

That is the confused-deputy model:

```text
low trust caller
  -> high trust driver
  -> high trust action
```

## 7. Why SCM Loading Is the Standard BYOVD Path

BYOVD mode uses:

- `OpenSCManagerW`
- `CreateServiceW`
- `OpenServiceW`
- `StartServiceW`

This is not exotic. Kernel drivers are Windows services of type `SERVICE_KERNEL_DRIVER`.

Why SCM is used:

- It is stable across Windows versions.
- It handles normal driver loading.
- It works with signed drivers.
- It is simpler than `NtLoadDriver`.
- It avoids manual mapping, which modern Windows strongly resists.

Why not manual-map:

- HVCI/DSE would object to unsigned/manual kernel code.
- BYOVD's whole purpose is to use signed code that Windows accepts.
- Manual mapping adds complexity unrelated to the vulnerability.

Detection downside:

- SCM driver creation/start is highly visible.
- Service name/path artifacts remain.
- Event logs/Sysmon/MDE can correlate it.

## 8. Why LPE Mode Waits for Service/Device Readiness

The code waits until the K7 service is running, then tries to open the device in a retry loop.

Why this exists:

- Service running does not mean the device object exists yet.
- Driver initialization can lag service state.
- The symbolic link may be created after driver start.
- Security product startup can be asynchronous.

Immediate failure would be unreliable. Retry makes the exploit robust against timing differences.

Trade-off:

- It can loop forever if the service never exposes the expected device.
- It can produce noisy repeated open attempts.
- A timeout would be safer for tooling quality.

## 9. Device Open Semantics

The code opens:

```text
\\.\DosK7RKScnDrv
```

with write access.

Why write access:

- The operation is command-style: "terminate this PID".
- No readback is needed.
- Requesting less than read/write/all access can sometimes succeed against stricter device ACLs.

What matters:

- Device object DACL.
- IOCTL access bits.
- Driver's own caller validation.
- Whether the device is created with secure open semantics.

If any of those are weak, a non-trusted caller can reach the privileged IOCTL.

## 10. Why PID Is the Input

The IOCTL input is a 4-byte PID.

Why PID is natural:

- Kernel can resolve PID to a process object.
- User mode can enumerate PIDs easily.
- PID is enough to identify a process at a point in time.

Why not pass process name:

- Kernel drivers generally operate on process objects/PIDs.
- Name matching is less authoritative.
- Process names can be spoofed.

Why PID is fragile:

- PID reuse can occur after process exit.
- Target can exit between enumeration and IOCTL.
- A stale PID can refer to a different process later.

Mitigation:

- Re-enumerate close to IOCTL send.
- Confirm process identity again if possible.
- Avoid long delay between finding PID and sending kill request.

## 11. Why Target-by-Name Exists

Security products are usually targeted by process name:

```text
edr.exe
avp.exe
MsMpEng.exe
sensor.exe
```

PIDs change:

- across boots,
- after service restart,
- after crash recovery,
- when watchdogs respawn processes.

The code uses Toolhelp process snapshot APIs to map names to PIDs.

Why Toolhelp:

- Simple.
- Stable.
- No kernel knowledge needed.
- Good enough for process-killer workflow.

Weakness:

- Race between enumeration and kill.
- Some protected processes may hide details or deny extra queries.
- Name-only matching can hit unintended processes with same name.

## 12. Why Looping Is Operationally Useful

The `looper` option repeatedly scans and kills.

Why:

- Security services restart.
- Watchdogs respawn agents.
- Service Control Manager can recover failed services.
- Attackers may need a window to run another payload while defenses remain down.

This is a user-mode persistence loop, not a kernel persistence mechanism.

Pros:

- Simple.
- No kernel hooks.
- Works against basic restart logic.

Cons:

- Very noisy.
- Obvious process-death pattern.
- Can destabilize the system.
- May trigger security product tamper alarms.

## 13. Why This Technique Has Lower BSOD Risk Than Memory R/W

Process-killer BYOVD usually has lower BSOD risk because:

- It does not write arbitrary kernel memory.
- It does not patch code.
- It does not change page tables.
- It uses the driver's intended operation path.

But lower does not mean zero.

BSOD or instability can happen if:

- The driver is incompatible with the OS.
- The driver mishandles invalid/stale PID input.
- The target process is critical.
- Killing a security/process supervisor triggers a buggy kernel callback path.
- The driver unloads unsafely.

The main risk is semantic instability, not memory corruption by the exploit itself.

## 14. Why It Is Less Version-Sensitive Than Token DKOM

K7Terminator does not need:

- `_EPROCESS` offsets.
- kernel base.
- CR3.
- page-table walk.
- token fast-ref handling.
- Win32k symbols.

It depends on:

- driver version,
- device path,
- IOCTL code,
- input buffer format,
- driver access control.

So the version sensitivity moves from Windows internals to vendor driver protocol.

This is a key distinction:

```text
ASTRA direct DKOM: OS-structure sensitive
K7 process killer: driver-protocol sensitive
```

## 15. Why This Is Easy to Productize

A process-kill primitive is easy to wrap:

```text
for target in process_names:
    find PID
    send PID to driver
```

This is why many BYOVD "terminator" tools look similar. The complexity is not in exploit math; it is in cataloging many drivers and their IOCTL formats.

The same controller pattern can support many drivers:

- K7RKScan
- BdApiUtil
- ThreatFire
- other AV/self-protection drivers

Each new driver only needs:

- service name,
- device name,
- IOCTL,
- buffer format.

## 16. Why It Is Also Easy to Detect Behaviorally

The generic pattern is also a defensive opportunity:

```text
driver service creation
  -> signed old AV/helper driver loaded
  -> user process opens driver device
  -> security process dies
  -> same process restarts/dies repeatedly
```

Even if the driver hash changes, the behavior cluster is suspicious.

Useful detections:

- Kernel service creation from user-writable paths.
- Driver load for security product not installed on host.
- Non-vendor process opening vendor driver device.
- Rapid termination of AV/EDR processes.
- Repeated termination loop.
- PPL process death without expected maintenance event.

## 17. Stability Across Windows Versions

The Windows OS version matters less than in ASTRA token DKOM, but it still matters.

Stable parts:

- SCM driver service model.
- Toolhelp process enumeration.
- Device open and `DeviceIoControl`.
- PID as process identifier.

Variable parts:

- Driver blocklist/WDAC policy.
- HVCI compatibility.
- PPL behavior of target security processes.
- Kernel APIs used internally by the driver.
- Whether the old driver can load on the OS.

So:

```text
The user-mode PoC is OS-stable.
The vulnerable driver is policy/version-sensitive.
```

## 18. Stability Across Driver Versions

Driver version is the dominant factor.

Could change:

- device name,
- IOCTL value,
- required access mask,
- input structure,
- caller validation,
- allowed target process classes,
- unload behavior.

Vendor fixes often do not need to rewrite the whole driver. They can simply:

- tighten device ACL,
- require signed/trusted caller,
- validate caller PID,
- block PPL/security process targets,
- remove the IOCTL.

That is enough to break this exploit.

## 19. BSOD Risk Matrix

| Action | Risk | Why |
|---|---|---|
| Register driver service | Low | Usually fails cleanly if denied. |
| Start old driver | Low-medium | Old driver may be incompatible. |
| Open device | Low | Usually returns invalid handle. |
| Send valid PID | Low | Intended driver operation. |
| Send stale PID | Low-medium | Depends on driver validation. |
| Kill normal user process | Low | Expected behavior. |
| Kill protected security process | Medium | Product self-defense/watchdog may react. |
| Kill critical Windows process | High | Can destabilize or reboot system. |
| Loop kill target | Medium | Repeated service disruption is noisy and unstable. |
| Driver unload | Medium | Some old drivers unload poorly. |

## 20. Why This Technique Is Useful for Ransomware

Ransomware operators often need:

- disable EDR,
- disable AV,
- disable backup agents,
- stop logging/monitoring,
- create a quiet window for encryption.

They do not always need:

- arbitrary kernel memory write,
- stealthy rootkit,
- long-term kernel persistence.

A process-killer driver is operationally efficient:

- minimal code,
- simple target list,
- fewer crashes,
- portable across many systems if driver loads,
- easy to integrate into tooling.

That is why process-killer BYOVD remains important even though it is less technically general.

## 21. Why This Does Not Give Full Kernel Control

Limitations:

- Cannot read kernel memory.
- Cannot write arbitrary kernel memory.
- Cannot change token directly.
- Cannot patch callbacks.
- Cannot inspect arbitrary kernel objects.
- Cannot bypass all defenses if driver is blocked.

The driver gives a command, not a memory primitive.

This matters for research classification:

```text
impact = defense evasion / privileged process control
not full arbitrary kernel R/W
```

## 22. How to Reason About Authorization Failure

The vulnerability is effectively:

```text
dangerous operation available to insufficiently trusted caller
```

Questions to ask:

- Who can open the device?
- What access mask is required?
- Does the driver check caller identity?
- Does it check admin/SYSTEM?
- Does it check vendor-signed caller?
- Does it restrict target PIDs?
- Does it block PPL/security processes?
- Is there a service broker that opens the device on behalf of users?

If a driver exposes powerful operations, access control is the boundary. If the boundary fails, the feature becomes a vulnerability.

## 23. Why PPL Is Not a Complete Defense

PPL protects against normal user-mode access. It does not stop every kernel-mode actor.

If an old signed driver says:

```text
I will terminate PID X for whoever can send this IOCTL
```

then PPL only matters if:

- the driver checks PPL,
- the kernel API refuses internally,
- policy blocks the driver,
- security product detects the attempt.

Otherwise, the driver acts as a privileged deputy.

This is why driver hygiene is part of PPL security.

## 24. Why WDAC/Blocklist Is the Real Mitigation

For this class, memory mitigations are not the main control.

SMEP/NX/kCFG/CET do not matter much because:

- no shellcode,
- no ROP,
- no code patch,
- no arbitrary kernel execution.

Better controls:

- Microsoft vulnerable driver blocklist.
- WDAC deny rules.
- Remove old drivers.
- Prevent unapproved kernel service creation.
- Monitor driver loads.
- Product vendor fix.

This is why BYOVD is often an application control problem as much as an exploit problem.

## 25. Reliability Improvements for the PoC

The public code is straightforward. A more robust research tool would add:

- timeout for LPE wait mode,
- driver hash/version validation,
- target process SID/path validation,
- denylist for critical Windows processes,
- exact `GetLastError()` logging for SCM/device/IOCTL,
- check whether process actually exited,
- optional one-shot vs monitor modes,
- cleanup behavior controls,
- telemetry-friendly dry-run mode.

These do not change the primitive. They improve safety and reproducibility.

## 26. Final Takeaway

K7RKScan exploitation is about abusing a high-level kernel operation, not building a memory primitive.

The engineering question is:

```text
Can an untrusted controller cause a trusted driver to terminate an arbitrary protected process?
```

If yes, the shortest path is not token stealing or page-table walking. The shortest path is to call the exposed kill operation reliably and repeatedly.

That is why this technique is simpler, more OS-version-stable, and usually less BSOD-prone than physical-memory exploitation, while still being highly valuable for defense evasion.


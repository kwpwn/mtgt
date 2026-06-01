# AV/EDR User-Mode Tamper and State Spoofing

Updated: 2026-05-27

## Purpose

This document classifies AV/EDR tamper ideas that do not start from a vulnerable
kernel driver. The goal is to separate them from BYOVD and kernel primitive
research, because the mental model is different.

For product-by-product self-protection case studies, start with:

- `docs/detection-and-mitigation/av-self-protection-research-index.md`
- `docs/detection-and-mitigation/av-case-microsoft-defender-self-protection.md`
- `docs/detection-and-mitigation/av-case-huorong-self-protection.md`
- `docs/detection-and-mitigation/av-case-qihoo-360-self-protection.md`

BYOVD usually looks like:

```text
signed vulnerable driver
  -> kernel primitive
  -> security object or telemetry state changes
```

User-mode AV/EDR tamper usually looks like:

```text
user-mode process
  -> product configuration, registry, service, file, update, or IPC surface
  -> local state, health reporting, update state, or visibility becomes inconsistent
```

The important question is not "is this kernel exploit?" The important question is:

```text
which product invariant is being contradicted?
```

## Classification Model

| Class | What Is Pressured | Typical Invariant | Common Failure Mode |
|---|---|---|---|
| State spoofing | Registry/config/status fields | Product status should reflect real sensor health | Product rewrites state or ignores local field |
| Version spoofing | Signature/platform/version metadata | "Current version" should mean current loaded content | Backend or engine uses another source of truth |
| Update interference | Signature/update files, directories, cache | Update success should imply usable files | File handles are released, path changes, self-protection blocks access |
| Service-state race | Service lifecycle and restart windows | Service state transitions should not create blind spots | Watchdog restarts, product hardening, timing mismatch |
| Sensor surface disruption | Local file/registry/network/IPC surface | Running product should collect expected events | Other sensors still observe the behavior |
| Console divergence | Local endpoint state vs cloud console state | Console should match endpoint reality | Cloud refresh invalidates stale or spoofed local state |

This class of technique is usually noisier and less universal than a real kernel
primitive. It depends on product-specific implementation details, protection
settings, and backend trust decisions.

## Case Study: SNEK Equinox

Source:

- https://github.com/The-SNEK-Initiative/SNEK_Equinox

Local reference copy:

- `90_sources/_temp_snek_equinox/`

### Classification

SNEK Equinox belongs here:

```text
AV/EDR user-mode tamper
  -> Defender state spoofing
  -> Defender signature metadata spoofing
  -> signature/update file locking
  -> claimed cloud/local telemetry divergence
```

It should not be classified as:

- BYOVD
- vulnerable-driver exploitation
- kernel LPE
- arbitrary kernel read/write
- DSE bypass
- PatchGuard bypass
- win32k exploitation

The repo has no driver component. The behavior is implemented with normal
user-mode Windows APIs, registry writes, service status notifications, directory
change monitoring, NT file opens, and file locks.

### Component Map

| File | Role | Behavior Class |
|---|---|---|
| `run.cpp` | Orchestrator | Starts the other binaries in sequence |
| `spoof.cpp` | Defender health state writer | Registry state spoofing |
| `vers.cpp` | Defender signature/version writer | Version metadata spoofing |
| `Equinox.cpp` | Long-running file-locking process | Signature/update interference |
| `build.bat` | Build helper | Tooling only |

The high-level behavior is:

```text
run.exe
  -> spoof.exe
       -> write Defender health-looking registry values
  -> vers.exe
       -> write Defender signature/platform-looking registry values
  -> Equinox.exe
       -> locate Defender definition update paths
       -> lock selected signature/update files
       -> monitor service and update directory changes
```

### What The README Claims

The upstream README says the project is a proof of concept for Defender EDR
telemetry spoofing. It claims a time-of-check/time-of-use style race around the
signature update mechanism, with the intended result that a console may show the
endpoint as protected while local protection is weakened.

The README also says the authors did not fully test or confirm the behavior.
That caveat matters. Treat the project as a hypothesis-backed PoC, not as a
proven universal Defender bypass.

### What The Code Actually Does

The code has two main behaviors.

First, it writes local Defender state and version metadata:

```text
HKLM\SOFTWARE\Microsoft\Windows Defender
HKLM\SOFTWARE\Microsoft\Windows Defender\Signature Updates
```

This is state spoofing. The code tries to make local product state look enabled,
running, and recently updated. The technique assumes some UI or reporting path
will read those fields, or at least be influenced by them.

Second, it opens Defender definition/update-related files and keeps exclusive
locks alive. The long-running process stores handles globally so the locks are
not released.

That is update/signature interference. The desired contradiction is:

```text
metadata says signatures are present/current
but file-level access or load behavior is disrupted
```

This is not the same thing as modifying the Defender engine or patching kernel
telemetry. It is closer to a product-state consistency attack:

```text
reported health
  != actual ability to load/use/update signature content
```

## Function-Level Behavior

### `run.cpp`

`run.cpp` is a simple launcher. It starts `spoof.exe`, waits for it to finish,
starts `vers.exe`, waits again, and then starts `Equinox.exe` with no visible
window.

Why it exists:

- the state spoofing step is separate from the file-locking step;
- registry writes need to happen before the long-running file-lock process;
- the final process must stay alive because file locks are tied to handles.

If `Equinox.exe` exits, the important file handles are closed and the locks are
released.

### `spoof.cpp`

`spoof.cpp` writes product-health-looking values under the Defender registry key.
The targeted fields include product state, running state, real-time protection,
on-access protection, and behavior monitoring.

Why it exists:

```text
some local status surfaces read configuration/state fields
  -> attacker-controlled state value can create a false local impression
```

The broken invariant is:

```text
"enabled-looking status" should mean the protection path is actually healthy
```

What can fail:

- Tamper Protection may block writes.
- Defender may rewrite the values.
- MDE or another backend may not trust these local values.
- The process may lack permission to write HKLM.
- The field semantics may differ by Defender version.

### `vers.cpp`

`vers.cpp` writes signature, engine, platform, and last-update-looking values.

Why it exists:

```text
version freshness is a trust signal
  -> stale or fake version fields may make a local view look current
```

The broken invariant is:

```text
"latest signature metadata" should correspond to real loaded signature data
```

What can fail:

- update services may recompute or overwrite metadata;
- Defender may validate loaded signature content elsewhere;
- backend inventory may use signed product telemetry rather than raw registry;
- hardcoded version values quickly become stale.

### `Equinox.cpp`

`Equinox.cpp` is the actual long-running interference component.

The main routine reads Defender's product app-data path, derives the definition
update directory, builds backup signature file paths, and attempts to lock them.
It also starts helper threads for service-state and directory-change monitoring.

Key functions:

| Function | Behavior | Why It Matters |
|---|---|---|
| `AddHd` | Stores handles in a global list | Keeps file locks alive for the process lifetime |
| `TryLk` | Opens and locks selected backup signature files | Creates the initial file-access contradiction |
| `UpdTh` | Locks a modified update file | Extends the interference to newly changed files |
| `WDCb` | Reacts to `WinDefend` service stop notification | Tries to lock signature content during service lifecycle changes |
| `WDTh` | Registers service notification for `WinDefend` | Watches for Defender service transitions |
| `MRTTh` | Monitors `C:\Windows\System32\MRT` for size changes | Applies the same lock idea to MRT-related changes |
| `wmain` | Initializes paths, locks, monitors, and update-directory watch loop | Coordinates the long-lived behavior |

The most important implementation idea is handle lifetime:

```text
open file
  -> lock file range
  -> keep handle reachable
  -> do not close process
```

Why this matters:

Windows file locks are not permanent object corruption. They are process and
handle-lifetime dependent. If the process dies, the handles close and the locks
go away. This makes the technique operationally fragile compared with kernel
state modification.

## Why This Is A Consistency Attack

SNEK Equinox is best understood as a consistency attack against Defender state:

```text
reported Defender state
  -> healthy/running/current

file/update reality
  -> selected signature/update files may be unavailable or racing
```

The attack is useful only if a consumer trusts the reported state more than the
actual engine/update health.

That distinction is central. A real kernel tamper technique might directly
change callback registration, process protection, minifilter state, or ETW
provider behavior. SNEK Equinox does not show that. It pressures the local
product control plane and file/update plane.

## Failure Modes And Research Questions

Useful questions when reading this kind of AV/EDR PoC:

- Which status surface reads the spoofed registry fields?
- Does the cloud console use raw local state, product-signed telemetry, or
  backend-computed health?
- Does Tamper Protection allow the registry writes?
- Are the definition file paths stable on current Defender builds?
- Does Defender retry, copy, memory-map, or validate signature content in a way
  that bypasses the attempted lock?
- Does the engine still have cached signatures already loaded in memory?
- What happens after a reboot?
- What happens if the long-running process exits?
- Does a product watchdog repair the state?
- Are service lifecycle notifications too late to win the race?
- Are file locks honored by the specific code path being pressured?

The "why" behind each question is the same:

```text
the PoC assumes a specific source of truth
```

If Defender or MDE uses a different source of truth, the spoof collapses.

## Where It Fits In The Repo

Use this classification:

```text
SNEK Equinox
  -> docs/detection-and-mitigation/av-edr-user-mode-tamper-spoofing.md
  -> not 03_byovd/
```

Related but distinct documents:

- `docs/detection-and-mitigation/av-self-protection-research-index.md`
- `docs/detection-and-mitigation/av-case-microsoft-defender-self-protection.md`
- `docs/detection-and-mitigation/av-case-huorong-self-protection.md`
- `docs/detection-and-mitigation/av-case-qihoo-360-self-protection.md`
- `docs/detection-and-mitigation/driver-evasion-pressure-map.md`
- `docs/detection-and-mitigation/minifilter-and-edr-visibility.md`
- `docs/detection-and-mitigation/etw-threat-intelligence-notes.md`
- `03_byovd/00_index-and-matrix/BYOVD_CALLBACK_SECURITY_STATE_TAMPER.md`

## Study Questions

1. Why is registry state spoofing weaker than kernel object tamper?
2. Why does handle lifetime matter for file-lock-based interference?
3. What does "console says healthy" prove, and what does it not prove?
4. Which component is the real source of truth: registry, service state, loaded
   engine state, update state, or cloud state?
5. Why should this case not be mixed into BYOVD notes?
6. Which assumptions would you need to verify before calling this a real
   telemetry spoof instead of a local consistency bug?

## References

- SNEK Equinox:
  https://github.com/The-SNEK-Initiative/SNEK_Equinox
- Microsoft Defender Antivirus configuration and management overview:
  https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows
- Microsoft Tamper Protection:
  https://learn.microsoft.com/en-us/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection

# COM Hijacking — Deep Dive

Complete reference: COM architecture internals, object activation flow, registry resolution,
HKCU override mechanics, auto-elevation, UAC bypass, and discovery methodology.

---

## 1. COM Architecture Overview

### What is COM?

Component Object Model (COM) is a binary interface standard introduced in Windows 3.1/NT and
still deeply embedded in Windows today. Every major Windows subsystem uses COM internally:
Explorer shell, Task Scheduler, WMI, Windows Update, Defender, Print Spooler, UAC elevation,
and hundreds of system services.

COM's purpose: allow objects implemented in one binary to be consumed by another binary,
across process boundaries, across machine boundaries, regardless of programming language.

### Core Concepts

**Interface**: A set of method signatures (virtual table layout). All COM objects implement
`IUnknown` at minimum (QueryInterface, AddRef, Release). All other functionality is exposed
through additional interfaces (IDispatch, IShellFolder, etc.).

**CLSID (Class Identifier)**: A 128-bit GUID uniquely identifying a COM class implementation.
Example: `{00021401-0000-0000-C000-000000000046}` is Shell.Application (the Explorer shell).

**ProgID (Programmatic Identifier)**: A human-readable string alias for a CLSID.
Example: `Shell.Application` maps to the CLSID above. Stored in registry under
`HKCR\Shell.Application\CLSID`.

**IID (Interface Identifier)**: GUID identifying a specific interface. When a client calls
`QueryInterface(IID_IShellFolder, &ptr)`, COM verifies the object supports that interface.

**GUID format in registry**: `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` — always braces,
always uppercase hex in registry.

---

## 2. COM Registration in the Registry

### Registry Layout

```
HKEY_CLASSES_ROOT\   ← merged view of HKLM\Software\Classes + HKCU\Software\Classes
  CLSID\
    {CLSID-GUID}\
      (Default) = "Human readable name"
      InprocServer32\
        (Default) = "C:\Windows\System32\something.dll"
        ThreadingModel = "Apartment" | "Free" | "Both" | "Neutral"
      LocalServer32\
        (Default) = "C:\Windows\System32\something.exe"
      ProgID\
        (Default) = "Application.ClassName.1"
      VersionIndependentProgID\
        (Default) = "Application.ClassName"
      AppID = "{AppID-GUID}"     ← optional, for out-of-process servers
```

### InprocServer32 vs LocalServer32

**InprocServer32**: The COM class is implemented as a DLL loaded into the **calling process**.
No separate process created. The DLL exports `DllGetClassObject()` and `DllCanUnloadNow()`.
This is how most lightweight COM objects work.

**LocalServer32**: The COM class runs in a **separate EXE process**. COM uses RPC/LPC
internally to marshal calls between caller and server. Used when the server needs its own
security context, or for out-of-process components like DCOM servers.

**Consequence for hijacking**: InprocServer32 hijacking causes attacker's DLL to load
directly into the elevated process's address space — immediate code execution at that
process's integrity/privilege level.

### AppID and DCOM

AppID registry key (`HKCR\AppID\{GUID}`) controls:
- Which identity runs the COM server (RunAs value)
- DCOM security (LaunchPermission, AccessPermission)
- Activation location (local vs remote)

When a COM class has an AppID with `RunAs = "Interactive User"` or a specific account,
the SCM (Service Control Manager) / DCOMLAUNCH service handles launching the server
process with the correct identity.

### HKCR: The Merged Hive

`HKEY_CLASSES_ROOT` is a **merged view**:
1. `HKCU\Software\Classes` — per-user registration (current user, no admin needed to write)
2. `HKLM\Software\Classes` — machine-wide registration (requires admin to write)

**Critical rule**: HKCU takes precedence over HKLM in this merge.

This is the root cause of COM hijacking: any standard user can write to HKCU\Software\Classes,
which overrides HKLM\Software\Classes for that user's session.

---

## 3. COM Object Activation Flow

### CoCreateInstance Internals

```c
HRESULT CoCreateInstance(
    REFCLSID  rclsid,     // which COM class to create
    LPUNKNOWN pUnkOuter,  // aggregation (usually NULL)
    DWORD     dwClsContext,// CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER | CLSCTX_ALL
    REFIID    riid,       // which interface to request
    LPVOID*   ppv         // output pointer
);
```

Internally, `CoCreateInstance` calls `CoGetClassObject` which:

```
1. Check COM apartment / context (MTA vs STA)
2. Consult CLSID registration:
   a. Check HKCU\Software\Classes\CLSID\{rclsid}  ← USER HIVE FIRST
   b. If not found: check HKLM\Software\Classes\CLSID\{rclsid}
   c. If not found: check HKCR\CLSID\{rclsid} (merged, same as above effectively)
3. Based on dwClsContext and what's registered:
   - InprocServer32 → load DLL into current process via LoadLibrary
   - LocalServer32  → launch EXE via CreateProcess (through SCM/DCOMLAUNCH)
4. Call DllGetClassObject (inproc) or connect to EXE via RPC (local server)
5. IClassFactory::CreateInstance → create actual object
6. QueryInterface for riid
```

### Step 2a is the attack surface

When an elevated process (SYSTEM, High integrity) calls `CoCreateInstance`:
- COM checks HKCU first — which is writable by the **current logged-in user** (Medium integrity)
- If attacker pre-registered a CLSID in HKCU → COM loads attacker's DLL into the elevated process
- Execution context: the elevated process's token (SYSTEM or High integrity)

---

## 4. COM Hijacking — Mechanism

### Type 1: HKCU Override (Most Common)

**Condition**: A privileged process loads a COM class via CLSID that is registered in HKLM
but NOT in HKCU for the current user.

**Attack steps**:
```
1. Identify elevated process calling CoCreateInstance for CLSID {X}
2. Verify: HKCU\Software\Classes\CLSID\{X} does NOT exist
3. Create:
   HKCU\Software\Classes\CLSID\{X}\InprocServer32\
       (Default) = "C:\Users\user\AppData\Local\Temp\evil.dll"
       ThreadingModel = "Apartment"
4. Wait for elevated process to activate COM object {X}
5. COM loader checks HKCU → finds our entry → loads evil.dll into elevated process
6. DllMain() runs at elevated process's integrity/privilege level
```

**Why no admin needed**: HKCU is always writable by the current user. Creating registry keys
under HKCU\Software\Classes never triggers a UAC prompt.

**DLL requirements**:
The attacker DLL must export `DllGetClassObject`. Without it, `CoLoadLibrary` will fail with
`REGDB_E_CLASSNOTREG` or similar, and the elevated process may handle the error gracefully.
However, many real-world targets call COM and do not check return values carefully, so even a
stub DLL that returns `E_NOTIMPL` from `DllGetClassObject` can cause DllMain to execute before
failure is reported.

Minimal DLL stub:
```c
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // code runs here at elevated context
        // e.g., add user to administrators, spawn elevated shell, etc.
    }
    return TRUE;
}

// Required export, can return failure after payload runs
__declspec(dllexport)
HRESULT DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID *ppv) {
    return E_NOTIMPL;
}
```

### Type 2: Missing / Phantom CLSID

An elevated process tries to activate a CLSID that has **no registration anywhere** (HKCU or
HKLM). `CoCreateInstance` would normally return `REGDB_E_CLASSNOTREG`. But the attacker can
register it in HKCU and provide a handler.

This is essentially the same technique but targets CLSIDs that were never registered (e.g.,
removed by Windows update, leftover from uninstalled software that still gets looked up).

### Type 3: DLL Path Override

Even if the CLSID is registered in both HKCU and HKLM, but the HKCU registration points the
`InprocServer32` path to a location writable by the user (e.g., because someone copied the
registration from HKLM and pointed to a user-writable path), the attacker can plant a DLL there.

---

## 5. Auto-Elevation COM Objects

### What is Auto-Elevation?

Windows Vista introduced User Account Control (UAC). To avoid constant elevation prompts for
routine system tasks, Microsoft marked certain built-in COM objects as "auto-elevate":
when a Medium integrity process activates them, Windows automatically elevates the activation
to High integrity **without showing a UAC prompt**.

Auto-elevation is controlled by two factors in the CLSID registry entry:
```
HKLM\Software\Classes\CLSID\{X}\Elevation\
    Enabled = 1 (DWORD)
```
And the COM server binary must be in a trusted location (`%windir%\System32` typically)
and signed by Microsoft.

### Auto-Elevation Object Examples

| CLSID | ProgID | Purpose |
|---|---|---|
| `{3E5FC7F9-9A51-4367-9063-A120244FBEC7}` | — | ColorDataProxy |
| `{D2E7041B-2927-42fb-8E9F-7CE93B6DC937}` | — | IFolderView |
| `{F87B28F1-DA9A-4F35-8EC0-800EFCF26B83}` | — | Folder shortcut |
| `{0A29FF9E-7F9C-4437-8B11-F424491E3931}` | — | Token broker |

Microsoft maintains an internal list. These are not publicly documented — they are discovered
through reverse engineering or ProcMon observation.

### UAC Bypass via Auto-Elevation COM

**Condition**: A Medium integrity process can activate a specific auto-elevation COM object
that exposes methods capable of executing arbitrary code.

**Classic example: ICMLuaUtil**

The COM object `{6EDD6D74-C007-4E75-B76A-E5740995E24C}` (auto-elevates) exposes
`IID_ICMLuaUtil` which includes methods like:
- `SetRegistryStringValue` — write to HKLM without admin prompt
- `ShellExec` — execute a program at elevated integrity

Attack:
```
Medium integrity process:
1. CoCreateInstance({6EDD6D74...}, CLSCTX_LOCAL_SERVER, IID_ICMLuaUtil, &pUtil)
   → COM auto-elevates to High integrity silently
2. pUtil->ShellExec("cmd.exe", ...) → High integrity cmd.exe, no UAC prompt
```

This was widely used until patched in later Windows 10 builds. Microsoft periodically patches
discovered auto-elevation objects by adding checks, reducing exposed interface methods, or
removing auto-elevation flags.

### COM Object Elevation Moniker

Alternative to auto-elevation: the **Elevation Moniker** `Elevation:Administrator!...`.
A process can request elevation of a specific COM class via:
```c
CoGetObject(L"Elevation:Administrator!clsid:{GUID}", &bindOpts, IID_IInterface, &p);
```
This always triggers a UAC prompt. Not a bypass, but useful to know for context.

---

## 6. DCOMLAUNCH and COM Activation Infrastructure

When a `LocalServer32` COM class is activated (out-of-process):

```
Caller process
    │
    └── RPC call → DCOMLAUNCH service (runs as SYSTEM)
                        │
                        ├── Check AppID for launch permission
                        ├── Determine RunAs identity
                        ├── CreateProcess as RunAs identity
                        └── Return interface proxy to caller
```

**DCOMLAUNCH** is the critical service that launches COM servers. It runs as SYSTEM and can
create processes as other users, SYSTEM, or the logged-in user depending on AppID configuration.

### AppID RunAs Misconfiguration

If an AppID has `RunAs = "Interactive User"` and the COM server binary is in a user-writable
location (or the CLSID is registerable in HKCU), there's potential for abuse:
- The COM server runs as whoever is currently logged in interactively
- If the logged-in user is an admin session but attacker controls COM server binary → execution
  in that session context

---

## 7. Discovery: Finding COM Hijack Targets

### Method 1: Process Monitor (ProcMon) — Gold Standard

**Setup filter**:
```
Column: Operation   | Relation: is    | Value: RegOpenKey → Include
Column: Result      | Relation: is    | Value: NAME NOT FOUND → Include
Column: Path        | Relation: contains | Value: \CLSID\ → Include
Column: Process Name| Relation: is    | Value: <target process> → Include (optional)
```

**Interpretation**:
- `NAME NOT FOUND` on a `RegOpenKey` for a CLSID path in HKCU means the app tried to find
  a CLSID registration in user hive, failed, then fell through to HKLM
- These are the exact CLSID lookups where HKCU override would intercept

**Targeted approach (Ferrum's method)**:
Run ProcMon while triggering actions in elevated processes. Filter to show:
```
Process: elevated (SYSTEM / LocalSystem / High integrity admin process)
Operation: RegOpenKey
Path: HKCU\Software\Classes\CLSID\{...}
Result: NAME NOT FOUND
```
Each such event = a candidate CLSID for hijacking.

**ProcMon filter XML** (import directly):
```xml
<ProcessMonitorFilter>
  <FilterRules>
    <FilterRule>
      <Column>Operation</Column>
      <Relation>is</Relation>
      <Value>RegOpenKey</Value>
      <Action>Include</Action>
    </FilterRule>
    <FilterRule>
      <Column>Result</Column>
      <Relation>is</Relation>
      <Value>NAME NOT FOUND</Value>
      <Action>Include</Action>
    </FilterRule>
    <FilterRule>
      <Column>Path</Column>
      <Relation>contains</Relation>
      <Value>CLSID</Value>
      <Action>Include</Action>
    </FilterRule>
  </FilterRules>
</ProcessMonitorFilter>
```

### Method 2: Registry Enumeration (Programmatic — Ferrum's Approach)

```go
// Ferrum's clsid module logic:
// 1. Enumerate all running processes, get their token integrity / account
// 2. For each SYSTEM/elevated process, note its identity
// 3. Enumerate HKLM\Software\Classes\CLSID\ — all registered CLSIDs
// 4. For each CLSID: check if HKCU\Software\Classes\CLSID\{same GUID} exists
// 5. If NOT found in HKCU → candidate (elevated process might look here first)

// PowerShell equivalent:
$hklmCLSIDs = Get-ChildItem "HKLM:\Software\Classes\CLSID" | Select -ExpandProperty PSChildName
foreach ($clsid in $hklmCLSIDs) {
    $hkcuPath = "HKCU:\Software\Classes\CLSID\$clsid"
    if (-not (Test-Path $hkcuPath)) {
        Write-Host "Candidate: $clsid"
    }
}
```

### Method 3: OleViewDotNet

OleViewDotNet (by James Forshaw) is the authoritative COM analysis tool:
- Browse all registered COM classes
- See AppID, elevation settings, RunAs configuration
- Test COM object activation
- View interface methods
- Find auto-elevation CLSIDs (`Elevation\Enabled = 1`)

```
OleViewDotNet → Registry → CLSID → Filter: "Elevation Enabled" = True
→ Lists all auto-elevation COM objects
→ For each: check what interfaces and methods are exposed
```

### Method 4: Seatbelt COM Surface Enumeration

```
Seatbelt.exe COMAutoElevations     → list auto-elevation COM CLSIDs
Seatbelt.exe InterestingFileACLs   → includes COM server DLL paths
```

### Method 5: Targeted Process Observation

For a specific process you want to target:
1. Attach ProcMon before process starts
2. Trigger every UI action / feature in the target process
3. Collect all HKCU CLSID lookups that returned NAME NOT FOUND
4. For each: verify InprocServer32 or LocalServer32 exists in HKLM
5. Those are your injection candidates

---

## 8. Confirming Exploitability

Not every HKCU CLSID miss is exploitable. Validation steps:

**Step 1**: Does an InprocServer32 or LocalServer32 exist in HKLM for this CLSID?
```
reg query "HKLM\Software\Classes\CLSID\{GUID}" /s
```
If InprocServer32 exists → DLL hijack candidate. If LocalServer32 → EXE hijack (harder).

**Step 2**: Is the process that looks up this CLSID running at elevated integrity?
- Use Process Hacker / Task Manager to check integrity level of the process
- Or: Ferrum's `enrichProcesses()` — inspects token, checks if SYSTEM/High

**Step 3**: Can we trigger the COM activation reliably?
- Does the elevated process activate this CLSID on demand (UI action, event, schedule)?
- Or is it only activated at startup (harder to time)?

**Step 4**: Is the ThreadingModel compatible?
- "Apartment" → DLL loaded in the STA thread (most common for UI processes, safe)
- "Free" → MTA thread
- "Both" / "Neutral" → either
- If ThreadingModel is missing in our HKCU registration, COM may refuse to load or deadlock

**Step 5**: Does the elevated process crash after DllGetClassObject fails?
- Test with a stub DLL that returns E_NOTIMPL
- If process crashes or shows error → may alert user or logging system

---

## 9. Specific High-Value COM Hijack Targets (Historical Reference)

These have been researched publicly. Some are patched, version-specific, or mitigated:

### Task Scheduler (taskschd.dll) CLSIDs
- Task Scheduler uses many COM activations during normal operation
- Runs tasks as SYSTEM or High integrity
- Many CLSID lookups historically missed HKCU check first
- Find by: running `taskschd.msc` with ProcMon attached

### Windows Explorer (explorer.exe) CLSIDs
- Explorer is a Medium integrity process but activates many COM objects
- If Explorer activates a CLSID that a High integrity COM server also uses → medium → high?
- More useful for persistence (runs at logon) than LPE

### MMC (mmc.exe) CLSIDs
- MMC often runs elevated (admin tools)
- Many snap-ins use COM
- ProcMon during MMC snap-in loading reveals many CLSID lookups

### Control Panel (control.exe) CLSIDs
- Historically many auto-elevation bypasses via control panel COM objects
- `fodhelper.exe` is a well-known example of a control-panel adjacent auto-elevating binary
  (not purely COM but uses COM internally)

### Consent.exe Adjacent CLSIDs
- Consent.exe handles UAC prompts; any COM it uses is auto-elevated
- Rarely exploitable directly, but adjacent infrastructure is a good research target

---

## 10. COM Hijacking for Persistence (vs LPE)

COM hijacking is also valuable for **persistence** (not just LPE):

**Persistence via Explorer CLSIDs**:
- Find a CLSID that explorer.exe activates at every logon
- Plant in HKCU
- DLL loads on every user logon
- Runs in explorer.exe context (Medium integrity for standard user, High for admin sessions)
- No new processes visible in process list (runs in explorer)
- Very stealthy — no autorun key, no scheduled task, no service

**Finding logon-time COM activations**:
```
1. Log out and back in with ProcMon running (boot-time capture)
2. Filter: explorer.exe + RegOpenKey + HKCU\...\CLSID + NAME NOT FOUND
3. These fire every logon → persistence candidates
```

---

## 11. Audio / DCOM Service Connection (Relevance to This Repo)

The Windows Audio service (`AudioSrv`) and `audiodg.exe` use COM extensively:
- AudioSrv is a LocalSystem service
- audiodg.exe runs as LOCAL SERVICE with restricted token
- COM activation between AudioSrv and audiodg.exe crosses a privilege boundary

Research relevance (see `docs/windows-internals/windows-audio-audiodg-lpe-research-notes.md`):
- audiodg.exe LPE often involves the COM/RPC channel between it and AudioSrv
- COM object activated by LocalSystem (AudioSrv) → if hijackable → code at LocalSystem
- Audio device graph API surface uses COM interfaces
- Check: ProcMon on svchost.exe hosting AudioSrv → CLSID lookups at SYSTEM integrity

---

## 12. Mitigations

### Windows Defender Application Control (WDAC)
- Can block COM object activation based on CLSID policy
- Can restrict InprocServer32 DLL loading to signed binaries only
- Strong mitigation against HKCU COM hijacking if DLL must be Microsoft-signed

### AppLocker
- DLL rules can block unsigned/untrusted DLLs from loading
- InprocServer32 DLL hijack would be blocked if DLL not in allowed path or not signed

### Protected Users Security Group
- Members cannot use NTLM, cannot delegate credentials
- Does NOT directly prevent COM hijacking, but reduces downstream token abuse

### UAC Token Filtering
- Standard user tokens are filtered even for local admin accounts
- COM auto-elevation objects are specifically gated to avoid token filter bypass
- Patching auto-elevation CLSIDs progressively removes this bypass surface

### HKCU Write Restrictions (Rare)
- In some hardened enterprise configurations, HKCU\Software\Classes writes can be audited
- Some AppContainer environments restrict HKCU COM registration
- Normally: no restriction. This is by design (per-user COM is a feature).

---

## 13. Detection

### Registry Audit (Event 4657)
Enable: `Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy → Object Access → Audit Registry`

```
Event ID 4657: A registry value was modified
  Key Name: \REGISTRY\USER\<SID>\Software\Classes\CLSID\{GUID}\InprocServer32
  Value Name: (Default)
  New Value: C:\Users\...\AppData\...\evil.dll
```

Alert on: Write to `HKCU\Software\Classes\CLSID\*\InprocServer32` or `LocalServer32`

### Sysmon Event 13 (Registry Value Set)
```xml
<RegistryEvent>
  <EventType>SetValue</EventType>
  <TargetObject>HKCU\Software\Classes\CLSID\{*}\InprocServer32\(Default)</TargetObject>
</RegistryEvent>
```

### DLL Load Anomaly
- Sysmon Event 7 (Image Loaded): DLL loaded from AppData / Temp by a system process
- Alert pattern: high-integrity process + DLL path under user profile
- High signal-to-noise because system processes never legitimately load DLLs from user profile

### Hunting Query (KQL / Defender ATP)
```kusto
DeviceRegistryEvents
| where RegistryKey contains "CLSID" 
    and RegistryKey contains "InprocServer32"
    and RegistryKey startswith "HKEY_CURRENT_USER"
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueData
| sort by Timestamp desc
```

---

## 14. Summary: The COM Hijacking Kill Chain

```
Reconnaissance:
    ProcMon (elevated process + CLSID + NAME NOT FOUND)
    OR: Ferrum --CLSID
    OR: reg enumeration (compare HKLM vs HKCU CLSIDs)
                │
                ▼
Validation:
    Is target process elevated? (SYSTEM / High integrity)
    Is InprocServer32 the registration type? (DLL, not EXE)
    Can we trigger COM activation reliably?
    ThreadingModel compatible?
                │
                ▼
Weaponize:
    Create HKCU\Software\Classes\CLSID\{TARGET}\InprocServer32\
        (Default) = path\to\payload.dll
        ThreadingModel = Apartment
    Craft payload.dll with DllMain payload + DllGetClassObject export
                │
                ▼
Trigger:
    Interact with elevated application to trigger COM activation
    OR: Wait for scheduled event / service timer
                │
                ▼
Impact:
    DllMain() runs at elevated process's integrity/privilege
    Code execution as SYSTEM (if target was SYSTEM-level process)
    Or: High integrity code execution → further escalation
```

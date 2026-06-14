# DLL Search Order Hijacking — Deep Dive

Windows DLL loader internals, search order algorithm, KnownDLLs protection, SafeDLLSearchMode,
all hijacking variants, and discovery methodology.

---

## 1. Windows DLL Loader Internals

### What Happens When LoadLibrary is Called

When a process calls `LoadLibrary("foo.dll")` or when the loader resolves an import at
process startup, the Windows loader (ntdll.dll's `LdrpLoadDll`) must find the DLL on disk.
The search follows a defined algorithm, and the first match wins.

The loader is implemented in `ntdll.dll`:
- `LdrpLoadDll` — top-level load dispatch
- `LdrpFindOrMapDll` — check if already mapped (by name, then by path)
- `LdrpSearchPath` — implements the search order algorithm
- `LdrpLoadKnownDll` — handle KnownDLLs section objects

### DLL Load Contexts

**Import resolution at process start**:
When a PE is loaded (EXE or DLL), the loader walks the Import Directory Table and resolves
all DLL dependencies. This happens before any application code runs. The loader uses the
search order for each import name.

**Explicit LoadLibrary call**:
Application code explicitly calls `LoadLibrary` / `LoadLibraryEx`. Same search order applies
unless `LOAD_WITH_ALTERED_SEARCH_PATH` flag is used (changes semantics slightly).

**Delay-loaded imports**:
Import is resolved on first call, not at startup. Same search order. Common in large
applications that optionally use features.

---

## 2. Default DLL Search Order

Microsoft documents the standard DLL search order (with SafeDLLSearchMode enabled, which
is the default since Windows XP SP2):

```
Priority  Location                                           Notes
────────  ─────────────────────────────────────────────────────────────────
  1       KnownDLLs section objects                          Pre-loaded, no disk access
  2       Application directory (directory of the EXE)       Highest priority on disk
  3       System directory — GetSystemDirectory()            Usually C:\Windows\System32
  4       16-bit system directory — C:\Windows\System        Legacy, rarely relevant
  5       Windows directory — GetWindowsDirectory()          C:\Windows
  6       Current working directory (CWD)                    ← Attack surface with SafeDLL ON
  7       Directories in %PATH% environment variable         ← Attack surface
```

**Without SafeDLLSearchMode (old behavior)**:
CWD was at priority 2 (right after application directory), making CWD hijacking trivial.
SafeDLLSearchMode moves CWD after System32/Windows directories.

**Registry control**:
```
HKLM\System\CurrentControlSet\Control\Session Manager
  SafeDLLSearchMode = 1  (enabled, default)
```

---

## 3. KnownDLLs — The Protection Mechanism

### What are KnownDLLs?

A set of commonly used Windows DLLs that are pre-loaded as **section objects** in the Windows
object namespace at system boot. When the loader needs one of these DLLs, it maps the existing
section object instead of searching the file system.

**Location in object namespace**: `\KnownDlls\`

```
\KnownDlls\
    ntdll.dll
    kernel32.dll
    kernelbase.dll
    advapi32.dll
    user32.dll
    gdi32.dll
    ole32.dll
    oleaut32.dll
    shell32.dll
    msvcrt.dll
    ... (50+ entries)
```

**Registry source** (populated at boot):
```
HKLM\System\CurrentControlSet\Control\Session Manager\KnownDLLs
```

**Effect**: A DLL in KnownDLLs **cannot be hijacked** by planting a fake copy in the
application directory or %PATH%. The loader never does a file system lookup for these.

**32-bit vs 64-bit**: Two separate KnownDlls lists:
- `\KnownDlls\` → 64-bit DLLs
- `\KnownDlls32\` → 32-bit DLLs (WOW64 subsystem)

A DLL not in KnownDlls on one architecture but in KnownDlls on the other is still
potentially hijackable for the architecture where it's absent.

### Viewing KnownDLLs

```
winobj.exe → \KnownDlls\ → lists all section objects
or:
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"
```

### KnownDLLs Bypass Attempts

KnownDLLs cannot be directly bypassed from user mode under normal conditions. However:
- **Name variation**: `Kernel32.DLL` vs `kernel32.dll` — case-insensitive comparison used,
  so this doesn't help
- **Absolute path LoadLibrary**: `LoadLibrary("C:\\Users\\user\\kernel32.dll")` — bypasses
  KnownDLLs by specifying an explicit path. Loader uses the given path directly.
- **DLL redirection** (manifest / .local): Can redirect specific imports, potentially overriding
  KnownDLLs for that application context (see Section 7)

---

## 4. Types of DLL Hijacking

### Type 1: Classic Search Order Hijacking

**Scenario**: A privileged process loads `foo.dll` (which is NOT in KnownDLLs). The process
EXE is located in `C:\Program Files\VulnerableApp\`. A user has write access to some
directory that appears before `C:\Windows\System32` in the search order.

**If the application directory is writable**:
```
C:\Program Files\VulnerableApp\foo.dll  ← plant here (if writable)
```
Loader finds it at priority 2 (application directory), before System32.

**If a directory early in %PATH% is user-writable**:
```
%PATH% = C:\Users\user\bin;C:\Windows\System32;...
Plant: C:\Users\user\bin\foo.dll
```
Loader reaches %PATH% search at priority 7, hits user-controlled directory first.

**Current Working Directory**:
If the privileged process is launched from a directory the user controls (e.g., user initiates
a subprocess from their home directory), CWD hijack is possible (priority 6).

### Type 2: Phantom DLL Hijacking

A privileged process attempts to load a DLL that **doesn't exist anywhere** on the system.
The process tries LoadLibrary, it fails (ERROR_MOD_NOT_FOUND), but the process handles the
failure gracefully and continues.

The attacker can plant a DLL at any searched location and it will be found.

**Why phantom DLLs exist**:
- Optional feature DLLs (loaded if present, ignored if not)
- Removed-but-still-referenced DLLs from software that partially uninstalled
- Version-specific DLLs (`msvc*140.dll` on a machine without that runtime)
- Debugging / profiler DLLs (only present on dev machines)
- Hardware-specific DLLs (only present when specific hardware is installed)

**Discovery**: ProcMon filter on `LoadImage` or `ReadFile` + result `NAME NOT FOUND` +
path matching DLL search locations.

### Type 3: DLL Side-Loading

**Different from search order hijacking**: The target application is not a system process but
a third-party application with a valid signed binary that loads a DLL from the same directory.

**Mechanism**: Many legitimate applications (signed, trusted) load DLLs from their own
directory without any path verification. If the application runs elevated (or as a service)
and its directory is user-writable:

```
C:\Program Files\SomeLegitApp\
  SomeLegitApp.exe    ← signed, runs as SYSTEM (service or scheduled task)
  version.dll         ← NOT present → attacker plants here → loaded automatically
```

**Side-loading vs hijacking distinction**:
- Search order hijacking: exploits the search path algorithm
- Side-loading: exploits an application explicitly or implicitly loading a DLL from its own
  directory (application-local DLL), where that directory happens to be writable

**Why it works**: App-local DLLs are loaded at priority 2 (application directory), before
System32. If the application's directory is writable, plant the DLL there.

### Type 4: WinSxS / Manifest Hijacking

**Windows Side-by-Side (WinSxS)**: Assembly manifests (`.manifest` files or embedded PE
resources) specify exact DLL versions and locations, bypassing normal search order. Manifests
are processed by the **fusion loader** (SxS activation context).

**Attack vectors**:
- Plant a fake `.manifest` file in the application directory (application manifest redirect)
- Use `<file>` elements in manifest to redirect DLL loads
- Manifest in application directory overrides embedded manifest in rare cases

**Less common** due to complexity and low prevalence of writable manifest paths.

### Type 5: DLL Planting (Absolute Path + Writable Location)

A privileged process calls `LoadLibrary("C:\\SomeWritableDir\\foo.dll")` with a hardcoded
path that the user can write to. Not a search-order issue — the path is explicit but writable.

**Common in**: Poorly written services, installers that load DLLs from temp directories,
applications loading plugins from user-accessible locations.

---

## 5. SafeDLLSearchMode Analysis

### What It Changes

With `SafeDLLSearchMode = 1`:
```
Before: App dir → CWD → System32 → Windows → %PATH%
After:  App dir → System32 → Windows → CWD → %PATH%
```
CWD drops from position 2 to position 6. This eliminates CWD hijacking in most cases.

### What It Does NOT Protect

- Application directory (priority 2) — if writable, still exploitable
- %PATH% directories — if any early PATH entry is user-writable, still exploitable
- Phantom DLLs — search still reaches all locations
- Side-loading — no change (app-local DLL is still priority 2)

### Per-Process Override

Processes can opt out of SafeDLLSearchMode with:
```c
SetDllDirectory("")  // empty string = safe mode on
SetDllDirectory(NULL) // NULL = restores CWD to search (bypasses safe mode!)
```
Some older applications call `SetDllDirectory(NULL)` thinking they're clearing a previous
`SetDllDirectory` call, but actually re-enabling the unsafe search order.

`LoadLibraryEx` with `LOAD_WITH_ALTERED_SEARCH_PATH`:
- If lpFileName is absolute: search starts from that DLL's directory
- Slightly different semantics but same general vulnerability surface

---

## 6. DLL Proxying — Making Hijacks Transparent

A naive DLL hijack (DLL with only DllMain payload and no exports) will crash the target
process because exported functions that the target expects to call are missing.

**DLL Proxying**: Create a DLL that:
1. Exports all functions the legitimate DLL exports
2. Each exported function forwards to the real DLL
3. DllMain contains the payload

**Approach 1: Export forwarding** (compile-time)
```c
// foo.dll hijack proxy for legitfoo.dll
// In .def file or pragmas:
#pragma comment(linker, "/EXPORT:FooFunction=C:\\Windows\\System32\\legitfoo.FooFunction")
```

**Approach 2: Runtime forwarding** (load-time patching)
```c
BOOL WINAPI DllMain(HINSTANCE hDLL, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        // 1. Load real DLL
        HMODULE hReal = LoadLibraryExA("C:\\Windows\\System32\\legitfoo.dll",
                                        NULL, LOAD_LIBRARY_AS_DATAFILE);
        // 2. Execute payload
        RunPayload();
    }
    return TRUE;
}

// Exported function that delegates to real DLL
__declspec(dllexport)
int WINAPI FooFunction(int arg) {
    typedef int (WINAPI *pfn)(int);
    pfn real = (pfn)GetProcAddress(GetModuleHandleA("legitfoo.dll"), "FooFunction");
    return real(arg);
}
```

**Tooling for proxy generation**:
- `SharpDllProxy` — generates proxy source from a real DLL's export table
- `dll-proxy-auto` — automated proxy DLL generation
- Manual: use `dumpbin /exports legitfoo.dll` to get export list, write proxy

---

## 7. DLL Redirection Mechanisms (Defense and Bypass)

### .local Redirection
If a file named `application.exe.local` exists in the application directory, the loader
redirects all DLL loads to first check the `.local` directory (or the same directory as
the EXE). This is an old compatibility mechanism.

### Manifest Redirection (Fusion/WinSxS)
Application manifest (`application.exe.manifest`) can specify assembly dependencies.
Fusion loader processes these before standard search order.

**Attacker use**: If an application directory is writable, drop a `.manifest` file to
redirect DLL loads to attacker-controlled locations.

---

## 8. Ferrum's DLL Hijacking Enumeration Logic

Ferrum's `dllsearch` module calls `win.EnumerateDLLSearchPathFindings()` which checks:

1. **%PATH% directory analysis**:
   - Split %PATH% into individual directories
   - For each: check if it's user-writable (ACL check)
   - Check if it appears before `C:\Windows\System32` in the search order
   - Flag user-writable directories that precede System32

2. **KnownDLLs cross-reference**:
   - Enumerate KnownDLLs registry
   - Flag processes loading DLLs that match KnownDLL names from non-standard paths
   (indicates someone bypassed KnownDLLs via absolute path)

3. **Writable application directories**:
   - Enumerate running processes → get binary path → get parent directory
   - Check ACL of that directory for current user write access
   - Elevated processes with writable binary directories → high severity

**Severity levels** (from Ferrum code):
- Info: DLL search path entry that's non-standard but read-only
- Medium: User-writable %PATH% directory (after System32)
- High: User-writable application directory of an elevated process
- Critical: Phantom DLL load detected (process tried + failed to load a DLL from writable loc)

---

## 9. Discovery Methodology

### Step 1: %PATH% Audit
```powershell
# Check each PATH entry for user writability
$env:PATH -split ';' | ForEach-Object {
    $path = $_
    if (Test-Path $path) {
        $acl = Get-Acl $path -ErrorAction SilentlyContinue
        $writable = $acl.Access | Where-Object {
            ($_.IdentityReference -match "Everyone|Users|Authenticated Users|$env:USERNAME") -and
            ($_.FileSystemRights -match "Write|FullControl|Modify")
        }
        if ($writable) {
            Write-Host "[WRITABLE] $path"
        }
    }
}
```

### Step 2: Process Monitor — Phantom DLL Detection
```
Filter setup:
  Operation: is: ReadFile or CreateFile or Load Image
  Result: is: NAME NOT FOUND
  Path: ends with: .dll
```
Every DLL that a process fails to find on disk = phantom DLL candidate for that process's
search path.

### Step 3: Elevated Process Directory ACL Check
```
accesschk.exe -uwdq "Users" "C:\Program Files"
accesschk.exe -uwdq "Authenticated Users" "C:\Program Files (x86)"
```
Flags any directory under Program Files writable by non-admin users. Compare with list of
services / elevated processes running from those directories.

### Step 4: Service Binary Directory Audit
```powershell
Get-WmiObject Win32_Service | Where-Object { $_.State -eq "Running" } | ForEach-Object {
    $path = $_.PathName -replace '"', '' -replace ' .*', ''  # extract binary path
    $dir = Split-Path $path -Parent
    $acl = Get-Acl $dir -ErrorAction SilentlyContinue
    $writable = $acl.Access | Where-Object {
        $_.IdentityReference -match "Users|Everyone|Authenticated" -and
        $_.FileSystemRights -match "Write|Modify|FullControl"
    }
    if ($writable) {
        Write-Host "[VULN] Service '$($_.Name)' binary dir writable: $dir"
    }
}
```

### Step 5: Check for DLL Loads from Writable Paths
Sysmon Event 7 (Image Loaded) + alert when:
- Loading process has elevated integrity
- DLL path is under user-writable location (AppData, Temp, %PATH% writable dir)

---

## 10. Specific High-Value DLL Hijack Targets

### version.dll — Universal Hijack Target
Many Windows applications load `version.dll` for file version queries. It's NOT in KnownDLLs
on 64-bit Windows, making it a common side-loading target.

```
If app directory is writable and app loads version.dll:
Plant: C:\Program Files\VulnerableApp\version.dll
```

version.dll exports: `GetFileVersionInfoA/W`, `VerQueryValueA/W`, etc.
Proxy DLL forwarding to `C:\Windows\System32\version.dll` works transparently.

### winhttp.dll — Service/Network App Target
Not in KnownDLLs. Used by WinHTTP clients, Windows Update components, many services.

### wlbsctrl.dll — Classic Windows LPE
Historically: IKE and AuthIP IPsec Keying Modules (IKEEXT) service ran as SYSTEM and
attempted to load `wlbsctrl.dll` which didn't exist. Any user could create the DLL in
a searched path → SYSTEM execution.
Status: Patched in later Windows 10 versions.

### amsi.dll — AMSI Bypass Context
Not a direct LPE, but: if an elevated PowerShell / .NET process loads amsi.dll from a
user-writable path → plant a stub AMSI DLL that returns AMSI_RESULT_CLEAN for all scans.
Bypasses AV scanning in that elevated process.

### DbgHelp.dll / Symsrv.dll
Many debugging tools load these from the application directory. Debug tools often run elevated.
Classic side-loading opportunity.

### Profiling DLLs
`COR_PROFILER` environment variable: .NET runtime loads the profiler DLL specified here.
If set to user-controlled path → code injection into any .NET process.
```
COR_PROFILER={GUID}
COR_PROFILER_PATH=C:\Users\user\evil.dll
COR_ENABLE_PROFILING=1
```
This affects NEW processes inheriting environment, not existing ones (unless process re-spawns).

---

## 11. Environment Variable Manipulation

Related to DLL hijacking — environment variables control loader behavior:

### %PATH%
Adding a malicious directory to the beginning of %PATH% (if modifiable for system scope):
```
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment
  Path = C:\evil;C:\Windows\System32;...
```
Requires admin to modify system PATH. But if user can modify user-scope PATH:
```
HKCU\Environment
  Path = C:\evil;%SystemRoot%\System32;...
```
User-scope PATH prepends to system PATH for that user's processes.

### %PATHEXT%
Controls which file extensions are treated as executables. Less relevant for DLL hijacking.

### COR_PROFILER / COR_PROFILER_PATH
See above — .NET profiler DLL injection.

### WINDIR / SYSTEMROOT Spoofing
These environment variables are normally fixed to `C:\Windows`. Setting them via user-scope
environment doesn't affect system processes directly but might affect scripts that use them.

---

## 12. Mitigations

### KnownDLLs (Built-in)
Core system DLLs pre-loaded as section objects. Cannot be hijacked via filesystem planting.
Mitigates: search order hijacking for those DLLs.

### SafeDLLSearchMode (Default On)
Moves CWD from priority 2 to priority 6.
Mitigates: most CWD-based hijacking.
Bypassed by: app-local directory hijacking, %PATH% attacks.

### WDAC / AppLocker DLL Rules
Require all loaded DLLs to:
- Be signed (WDAC: Microsoft-signed or allow-listed signer)
- Be in allowed paths (AppLocker: whitelist by path or publisher)
Strongly mitigates DLL hijacking when properly configured.

### DLL Load Callback (Process Mitigation)
`SetProcessMitigationPolicy(ProcessImageLoadPolicy)`:
- `PreferSystem32Images` → prefer System32 over application directory for same-named DLLs
- `NoRemoteImages` → block DLL loads from network paths
- `NoLowMandatoryLabelImages` → block DLL loads from low-integrity paths

### Safe DLL Loading (Manifest Pinning)
Using activation contexts / manifests to pin specific DLL versions and locations prevents
substitution.

---

## 13. Detection

### Sysmon Event 7: Image Loaded
Most valuable. Log all DLL loads from:
- `AppData\` paths
- `\Temp\` paths
- `\ProgramData\` (when process is elevated)
- Any path not matching `C:\Windows\` for a high-integrity process

Alert rule: image loaded by SYSTEM process from non-System32 path.

### Process Monitor: LoadImage from Unexpected Path
Real-time monitoring with filters to catch phantom DLL load attempts before planting.

### Windows Defender Exploit Guard
Configure `Attack Surface Reduction` rule:
- Block process creations from PSExec and WMI commands
- Block untrusted and unsigned processes from USB (adjacent but useful)
- Enable `Block DLL loading not signed` ASR rule (requires WDAC complement)

### AV/EDR Signature Detection
- Many DLL hijacking payloads are well-known (version.dll proxy templates)
- EDR behavioral: flag when a high-integrity process loads a DLL from user-writable path

---

## 14. Summary

```
DLL Hijacking Attack Decision Tree:

Target: elevated process (service/scheduled task/UAC-elevated app)
    │
    ├── Does process load any DLL NOT in KnownDLLs?
    │     → Yes: potential candidate
    │     → No: limited options (absolute path override, manifest)
    │
    ├── Is the process's application directory writable?
    │     → Yes: plant DLL there (priority 2 in search order)
    │
    ├── Is any directory early in system %PATH% user-writable?
    │     → Yes: plant DLL in that directory (priority 7 but before later PATH entries)
    │
    ├── Does the process try to load a DLL that doesn't exist? (phantom)
    │     → Yes: plant anywhere in the search path
    │
    └── Is there an explicit LoadLibrary with a path in a writable location?
          → Yes: DLL planting (not search-order, but same effect)

Payload:
    Simple DLL? → May crash target (missing exports)
    Proxy DLL?  → Transparent hijack (forward real exports)
    Tool: SharpDllProxy to auto-generate proxy source
```

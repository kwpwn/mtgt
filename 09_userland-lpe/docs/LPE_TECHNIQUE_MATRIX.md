# Userland LPE Technique Matrix

Windows Local Privilege Escalation from userland perspective — covering misconfigurations,
design-level weaknesses, and Windows architectural attack surfaces. Each technique links
to a dedicated deep-dive document.

---

## Attack Chain Context

```
Initial Access (low/medium integrity user)
    │
    ├── Misconfiguration-based LPE
    │     ├── Service misconfig (unquoted path, weak ACL, writable binary)
    │     ├── Registry permission (writable service key → ImagePath)
    │     ├── Scheduled task abuse (writable task file, DLL hijack via task)
    │     └── Startup/autorun (writable autorun location)
    │
    ├── DLL/COM loading abuse
    │     ├── COM hijacking (HKCU override, auto-elevation, UAC bypass)
    │     ├── DLL search order hijacking (writable dir in PATH, phantom DLL)
    │     └── DLL side-loading (unsigned app loads from writable path)
    │
    ├── IPC / privilege boundary crossing
    │     ├── Named pipe impersonation (ImpersonateNamedPipeClient)
    │     └── Token theft via pipe connect trick (Potato family)
    │
    ├── Token / privilege abuse
    │     ├── SeImpersonatePrivilege → Potato / PrintSpoofer
    │     ├── SeDebugPrivilege → inject / dump
    │     ├── SeLoadDriverPrivilege → load arbitrary kernel driver → BYOVD
    │     ├── SeCreateTokenPrivilege → craft token
    │     └── SeTcbPrivilege → act as OS
    │
    └── Environment / policy gaps
          ├── PATH hijacking (writable dir early in %PATH%)
          └── Group Policy misconfiguration (writable GPO path, startup script)

After achieving SYSTEM (userland) → optional escalation to kernel:
    → SeLoadDriverPrivilege path → BYOVD chain (see 03_byovd/)
    → Token with SeTcbPrivilege → craft arbitrary token → kernel callbacks irrelevant
```

---

## Full Technique Matrix

| # | Technique | Prerequisite | Reliability | Stealth | Detect Difficulty | Deep Dive |
|---|---|---|---|---|---|---|
| 1 | COM hijacking (HKCU override) | Medium integrity | High | Medium | Medium | [doc 01](01_com-hijacking-deep-dive.md) |
| 2 | COM hijacking (auto-elevation) | Low integrity + known target | Medium | High | Hard | [doc 01](01_com-hijacking-deep-dive.md) |
| 3 | COM UAC bypass | Medium integrity | High (version-dep) | High | Hard | [doc 01](01_com-hijacking-deep-dive.md) |
| 4 | DLL search order hijacking | Writable dir in search path | Medium | High | Hard | [doc 02](02_dll-search-order-hijacking.md) |
| 5 | DLL side-loading | Writable app directory | High (app-dep) | High | Hard | [doc 02](02_dll-search-order-hijacking.md) |
| 6 | Phantom DLL hijacking | Missing DLL loaded by priv process | Medium | Very High | Very Hard | [doc 02](02_dll-search-order-hijacking.md) |
| 7 | Unquoted service path | Service with spaces, no quotes | High | Low | Easy | [doc 03](03_service-misconfiguration-lpe.md) |
| 8 | Weak service DACL | SC_MANAGER_CHANGE_CONFIG | High | Low | Easy | [doc 03](03_service-misconfiguration-lpe.md) |
| 9 | Writable service binary | Write access to service EXE | High | Low | Medium | [doc 03](03_service-misconfiguration-lpe.md) |
| 10 | Service registry key writable | Write to HKLM\...\Services\X | High | Medium | Medium | [doc 07](07_registry-permission-lpe.md) |
| 11 | SeImpersonatePrivilege (Potato) | Service account / IIS | Very High | Medium | Medium | [doc 04](04_token-privilege-abuse.md) |
| 12 | SeDebugPrivilege | Admin-equivalent + token has it | Very High | Medium | Medium | [doc 04](04_token-privilege-abuse.md) |
| 13 | SeLoadDriverPrivilege | Non-admin with this priv | High | Low | Medium | [doc 04](04_token-privilege-abuse.md) |
| 14 | SeCreateTokenPrivilege | Rare — requires driver/service | High | High | Hard | [doc 04](04_token-privilege-abuse.md) |
| 15 | SeTcbPrivilege | Rare system account | Very High | High | Hard | [doc 04](04_token-privilege-abuse.md) |
| 16 | SeAssignPrimaryTokenPrivilege | Service account with this priv | High | Medium | Hard | [doc 04](04_token-privilege-abuse.md) |
| 17 | Named pipe impersonation | Service creates accessible pipe | High | High | Hard | [doc 05](05_named-pipe-impersonation.md) |
| 18 | PrintSpoofer | SeImpersonatePrivilege + Spooler | Very High | Medium | Medium | [doc 05](05_named-pipe-impersonation.md) |
| 19 | Scheduled task — writable task | Write to task XML in \Tasks | High | Low | Easy | [doc 06](06_scheduled-task-abuse.md) |
| 20 | Scheduled task — binary hijack | Task runs writable binary | High | Low | Easy | [doc 06](06_scheduled-task-abuse.md) |
| 21 | Registry autorun writable | Write to Run/RunOnce keys | Medium | Low | Easy | [doc 07](07_registry-permission-lpe.md) |
| 22 | PATH hijacking | Writable dir early in %PATH% | Medium | High | Hard | [doc 07](07_registry-permission-lpe.md) |

---

## Prerequisites Breakdown

### Integrity Level Required
```
Low Integrity:
  - COM auto-elevation bypass (specific targets only)
  - Named pipe connect (if pipe ACL allows Everyone)

Medium Integrity (standard user):
  - Most misconfiguration-based techniques
  - COM HKCU hijacking (always writable by current user)
  - DLL hijacking (if writable path exists)
  - Token abuse (if privilege is present)

High Integrity (admin, no SYSTEM):
  - SeDebugPrivilege paths
  - Some kernel driver loading paths
  → Typically already have SYSTEM via other means
```

### Common Starting Contexts
```
IIS / Web Service (NetworkService / AppPool):
  → SeImpersonatePrivilege almost always present
  → Potato family → SYSTEM

SQL Server (mssqlserver / local service):
  → SeImpersonatePrivilege present
  → Potato family → SYSTEM

RDP / Interactive user session (standard):
  → Enumerate misconfigs (service, DLL, COM)
  → Check for writable high-priv service paths

Scheduled Task running user context:
  → Check task output for credential leaks
  → Look for writable binary paths in task definitions
```

---

## Detection Coverage Per Technique

| Technique | ETW Events | Sysmon | AV/EDR Behavior |
|---|---|---|---|
| COM hijacking (HKCU) | 4657 (reg write) | Event 13 (reg) | High FP rate, usually not alerted |
| DLL hijack | 7 (Image Load) | Image load path anomaly | Moderate detection |
| Unquoted service path | 7045/4697 | Process create from odd path | Easy — non-standard binary path |
| Weak service DACL | 4697 | Service config change | Moderate |
| SeImpersonatePrivilege | 4672 (sensitive priv) | — | Potato family well-sig'd |
| Named pipe impersonation | 5145 (pipe access) | Named pipe events | Hard to detect without pipe audit |
| Scheduled task modify | 4698/4702 | — | Easy if task created/modified |
| Registry autorun write | 4657 | Event 13 | Low-medium |
| PATH hijacking | — | Image load from unexpected path | Hard |

---

## Relationship to Kernel-Level Research

These userland LPE techniques are the **prerequisite layer** before kernel exploitation in many attack chains:

```
SeLoadDriverPrivilege
    → Load unsigned/vulnerable driver without DSE bypass
    → Direct BYOVD without needing kernel write primitive to disable DSE
    → See: 03_byovd/ for what to do with a loaded driver

SeDebugPrivilege
    → Open any process with PROCESS_ALL_ACCESS
    → Inject shellcode into SYSTEM process
    → Or: patch LSASS protections from userland before kernel work

COM hijacking → audiodg.exe / SYSTEM audio service
    → Matches: docs/windows-internals/windows-audio-audiodg-lpe-research-notes.md
    → AudioDG runs as LOCAL SERVICE → COM activation → potential service boundary cross

Named pipe impersonation → SYSTEM token
    → With SYSTEM token: load vulnerable driver as SYSTEM (required for kernel drivers)
    → Chain: low priv → Potato → SYSTEM → BYOVD driver load → kernel primitive
```

---

## Discovery Tool Reference

| Tool | Best For | Command Pattern |
|---|---|---|
| `accesschk.exe` | Service/file/registry ACLs | `accesschk -uwcqv "Users" *` |
| `winPEAS` | Automated full scan | `winPEAS.exe all` |
| `PowerUp.ps1` | PowerShell service/path enum | `Invoke-AllChecks` |
| `Seatbelt` | Token, privilege, COM surface | `Seatbelt.exe -group=all` |
| `Process Monitor` | COM/DLL hijack discovery | Filter: RegOpenKey + NAME NOT FOUND |
| `OleViewDotNet` | COM object inspection | CLSID browser, elevation moniker |
| `pipelist.exe` | Named pipe enumeration | `pipelist.exe` |
| `accesschk -p` | Process token inspection | `accesschk -p <pid>` |
| `whoami /priv` | Current token privileges | — |
| `sc.exe sdshow` | Service DACL | `sc.exe sdshow <service>` |
| `icacls` | File/directory ACL | `icacls "C:\Program Files\X"` |
| `Ferrum` | Automated surface triage | `ferrum.exe --ALL` |

---

## Windows Version Notes

Many techniques are version-dependent. Key inflection points:

| Windows Version | Notable LPE changes |
|---|---|
| XP/Vista | Token kidnapping (NtImpersonateThread), unpatched everywhere |
| Win7 | UAC introduced; many COM auto-elevation CLSIDs added |
| Win8/8.1 | AppContainer/low integrity hardened; more COM mitigation |
| Win10 1507-1607 | Many COM UAC bypass CLSIDs present; Hot Potato era |
| Win10 1703+ | Hot Potato patched; newer spoofer techniques emerge |
| Win10 1809+ | RoguePotato era; PrintSpoofer targets Spooler service |
| Win11 | PrintNightmare patches; many pipe-based vectors reduced |
| Win11 22H2+ | SeImpersonatePrivilege restrictions for AppContainer tightened |

Always note build number when documenting a technique. Do not assume universal applicability.

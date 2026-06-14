# 09 — Userland LPE Research

Local Privilege Escalation (LPE) techniques at the Windows userland layer — misconfigurations,
architectural design weaknesses, and IPC privilege boundaries. This directory bridges the gap
between initial access (standard user) and kernel-level exploitation (BYOVD, driver abuse).

Inspired by the module structure of `kernelstub/Ferrum` — a Go-based Windows LPE enumeration
framework. Ferrum's code is used as a reference for WHAT attackers look for; this resource
explains WHY each technique works at the Windows internals level and HOW defenders can detect it.

---

## Directory Map

```
09_userland-lpe/
  docs/
    LPE_TECHNIQUE_MATRIX.md          ← technique overview, prereqs, detection coverage
    01_com-hijacking-deep-dive.md    ← COM internals, HKCU override, auto-elevation, UAC bypass
    02_dll-search-order-hijacking.md ← loader internals, KnownDLLs, SafeDLLSearchMode, DLL proxy
    03_service-misconfiguration-lpe.md ← SCM, unquoted paths, weak DACLs, svchost DLL
    04_token-privilege-abuse.md      ← tokens, MIC, all dangerous privileges, Potato family
    05_named-pipe-impersonation.md   ← IPC internals, ImpersonateNamedPipeClient, PrintSpoofer
    06_scheduled-task-abuse.md       ← Task Scheduler, XML format, writable task vectors
    07_registry-permission-lpe.md    ← registry ACL model, service keys, AlwaysInstallElevated
    DISCOVERY_METHODOLOGY.md         ← tool chain, ProcMon filters, manual audit checklist
```

---

## Attack Chain Position

```
Initial Access (any context)
        │
        ▼
THIS DIRECTORY: Userland LPE Techniques
    COM hijacking → code in elevated process
    Service misconfiguration → SYSTEM via SCM
    Token abuse (SeImpersonatePrivilege) → Potato → SYSTEM
    DLL hijacking → code in privileged process
    Named pipe impersonation → SYSTEM token
    Registry key manipulation → service binary redirect
    Scheduled task exploitation → SYSTEM execution
        │
        ▼
Achieve NT AUTHORITY\SYSTEM (userland)
        │
        ├── If goal is credential access:
        │     → LSASS dump (with SeDebugPrivilege / SYSTEM)
        │     → SAM/SECURITY/SYSTEM hive extraction
        │
        └── If goal is kernel compromise (EDR kill, full rootkit):
              → SeLoadDriverPrivilege path: NtLoadDriver → vulnerable driver
              → SYSTEM token path: load driver as SYSTEM via sc.exe
              → See: 03_byovd/ for driver exploitation
              → See: 08_amd_byovd_edr_full/ for specific AMD chain
```

---

## Key Documents by Goal

**Understand COM internals and why HKCU overrides HKLM**:
→ `docs/01_com-hijacking-deep-dive.md` § 2-3

**Find COM hijack targets in a target environment**:
→ `docs/01_com-hijacking-deep-dive.md` § 7-8
→ `docs/DISCOVERY_METHODOLOGY.md` § 5 (ProcMon filter recipe 1)

**Understand why SeImpersonatePrivilege → SYSTEM**:
→ `docs/04_token-privilege-abuse.md` § 5 (Potato family section)
→ `docs/05_named-pipe-impersonation.md` § 2-3

**Map token privileges to LPE paths**:
→ `docs/04_token-privilege-abuse.md` § 17 (reference card)

**Understand SeLoadDriverPrivilege → BYOVD link**:
→ `docs/04_token-privilege-abuse.md` § 7

**Audit services systematically**:
→ `docs/03_service-misconfiguration-lpe.md` § 10 (tools)
→ `docs/DISCOVERY_METHODOLOGY.md` § 3 (manual investigation)

**Run automated discovery with Ferrum**:
→ `docs/DISCOVERY_METHODOLOGY.md` § 2

**Understand technique detection and telemetry**:
→ Each doc's Detection section
→ `docs/LPE_TECHNIQUE_MATRIX.md` (Detection Coverage column)

---

## Relationship to Other Directories

| This resource | Connects to |
|---|---|
| `SeLoadDriverPrivilege` LPE | `03_byovd/` — what to do with a loaded driver |
| COM hijacking (audiodg) | `docs/windows-internals/windows-audio-audiodg-lpe-research-notes.md` |
| LSASS dump via SeDebugPrivilege | `docs/detection-and-mitigation/edr-internals-complete-deep-dive.md` |
| Named pipe + token → SYSTEM | `08_amd_byovd_edr_full/` — SYSTEM required to load AMD driver |
| EDR detection of LPE techniques | `docs/detection-and-mitigation/` directory |

---

## Ferrum Reference

Ferrum (`kernelstub/Ferrum`) is a Go security enumeration framework with 13 modules:
`advanced`, `clsid`, `dllsearch`, `drivers`, `env`, `mitigations`, `pipes`, `policy`,
`registry`, `scheduled`, `services`, `startup`, `tokens`.

All modules are **enumeration only** — they find attack surface but do not exploit.
The research value: Ferrum's code shows exact heuristics that attackers use to find LPE
opportunities. Each doc in this directory explains the underlying Windows internals behind
what Ferrum detects.

Ferrum usage for quick triage:
```
ferrum.exe --ALL --OUTPUT lpe_report_$(hostname).txt
```

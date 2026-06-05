# Windows Internals Abuse Surface Atlas 2026

Backlinks: [topic index](../research-index/topic-index.md) | [IPC atlas](windows-ipc-boundary-atlas.md) | [COM/RPC notes](com-and-rpc-research-notes.md) | [ALPC notes](alpc-research-notes.md) | [Object Manager](../windows-internals/object-manager-and-handle-tables.md)

## Purpose

This document reads Windows like a researcher: start from the subsystems described in Windows Internals, ask "where is the boundary?", then map the bug classes and abuse patterns that have appeared in public research. The focus is COM, RPC, ALPC, IPC, Object Manager, file/registry/link behavior, service identity, desktop/session boundaries, CLFS/Cloud Files, Win32k/DWM/CTF, token/privilege behavior, and driver objects.

Safety rule:

```text
Do not record exploit chains, trigger buffers, payloads, patch bytes, shellcode, token stealing code, EDR bypass recipes, or command runbooks.
Record only: boundary -> invariant -> abuse primitive -> public case -> telemetry -> mitigation -> research questions.
```

## Research Lens

Windows Internals is not just `_EPROCESS`, `_TOKEN`, `_OBJECT_HEADER`, handle tables, or other structures. Each chapter should be read as a trust model:

| Internals area | Researcher question | Common abuse class |
|---|---|---|
| Object Manager | Who can create a name? Who resolves it? Can a symbolic link retarget it? | object namespace redirection, path lookup race, section/port/object pre-creation |
| Security Reference Monitor | Was an access check forced? Is the caller user mode or kernel mode? | missing access check, `RequestorMode` confusion, wrong access mask |
| Process/Thread/Token | Which token is active? What impersonation level is in use? Which privileges are enabled? | confused deputy, token impersonation, handle duplication, PPL trust abuse |
| I/O Manager | Where did the IRP originate? Is `SL_FORCE_ACCESS_CHECK` preserved? | device/file open confusion, arbitrary file operation, filter trust break |
| ALPC/RPC | Which endpoint is used? Is server identity authenticated? | endpoint spoofing, impersonation abuse, stale or missing server identity check |
| COM/DCOM | Does activation policy differ from invocation policy? Is an object remoted by reference? | COM hijack, trapped object, arbitrary CLSID creation, elevation moniker abuse |
| Registry/Config Manager | Can HKCU shadow HKLM? Are REG_LINK or registry symlinks involved? | class handler hijack, policy redirection, service/task config abuse |
| Memory Manager | Where are sections, pages, PTEs, COW, or KASLR leaks? | information leak, section interception, data-only primitive, page-table abuse |
| Win32k/DWM/CTF | Which session or desktop boundary exists? Can GUI objects cross integrity boundaries? | desktop broker confusion, CTF object abuse, DWM/ALPC information leak |
| CLFS/Cloud Files/Filters | What file is parsed before verification? Where can reparse/oplock/cloud callbacks intervene? | log-file parser corruption, symlink/junction abuse, false file immutability |

## Windows Internals Reading Map

Read Windows Internals by separating "legitimate mechanism" from "condition that can be abused." A good chapter should not only explain what an API does; it should answer who can call it, where the object lives, when access is checked, and whether state can change between check and use.

| Windows Internals topic | Abuse lens | Sources/cases to pair |
|---|---|---|
| System architecture and services | Which broker runs privileged? Which IPC surface does it expose? | COM elevation, SCM, Task Scheduler, WMI, BITS |
| Processes, threads, and jobs | Which primary or impersonation token is active? Which handles cross process boundaries? | PhantomRPC, named pipe impersonation, service account abuse |
| Security Reference Monitor | Which subject context is used for access checks? Is a privilege present or enabled? | `RequestorMode`/`SL_FORCE_ACCESS_CHECK`, SeImpersonate, PPL trust abuse |
| Object Manager | Which directory owns the object name? Can the caller pre-create or symlink it? | Project Zero object directory/path race, GreenPlasma |
| Registry and configuration | Does lookup pass through HKCU, HKLM, or HKCR? Can REG_LINK or class shadowing appear? | Eventvwr HKCU hijack, COM registry class confusion |
| Memory manager | Which address leak weakens KASLR? Can sections/PTEs/COW/MDLs become primitives? | DWM information disclosure, I/O ring primitive, page-table research |
| I/O manager and drivers | How does the IRP/IOCTL trust the caller? Which buffer method is used? Which device ACL applies? | BYOVD, METHOD_NEITHER, arbitrary kernel read/write classes |
| File systems and filters | Is the path verified as a string or as the final object? Can reparse/cloud/oplock change timing? | Cloud Files trapping, CLFS parser bugs, minifilter trust gaps |
| Networking | Which driver sees the packet or flow? Can RPC/SMB/named pipes bridge into identity? | ComoDoS/Inspect.sys, NTLM coercion, RPC endpoint abuse |
| Windowing and sessions | Can window station, desktop, or session objects cross integrity boundaries? | CTF, DWM, Winlogon desktop, GUI kernel attack surface |

## Source Confidence

| Source type | How to use it | Reason |
|---|---|---|
| Microsoft docs/MSRC/security blog | Treat as primary for affected component, mitigation, and terminology | Most stable source for APIs, patches, mitigations, and official boundaries |
| Project Zero / Microsoft researcher / established vendor research | Treat as high-confidence bug-class explanation | Usually includes root cause, version context, and mitigation discussion |
| Academic 2026 paper | Treat as research method and vulnerability-class map | Strong for modeling, fuzzing, and measurement, but individual CVEs still need case verification |
| Independent blog with PoC or stripped PoC | Treat as a case-study lead, not final truth | Often excellent for thinking, but should be verified against MSRC/build/repro details |
| GitHub PoC/forum/social post | Treat as queue item only | Extract claims, affected build, primitive, and telemetry; do not import recipes |

## Master Abuse Matrix

| Surface | Abuse question | Public examples to study | What broke | Defensive model |
|---|---|---|---|---|
| COM local service | Can low-privileged clients activate or influence elevated COM classes? | SLYP COM paper 2026, CVE-2026-21508, Project Zero trapped COM | activation/registry/impersonation/object-remoting assumptions | COM activation logs, registry class changes, process/module lineage |
| DCOM/trapped object | Can a server return or create an unsafe object by reference? | Project Zero trapped COM 2025, IBM lateral movement follow-up | remoted object remains in privileged server context | DCOM hardening, COM security config, unusual type-library/object use |
| RPC over ALPC | Can a privileged client be coerced into an attacker-controlled or spoofed endpoint? | Securelist PhantomRPC 2026 | server identity is not strongly bound to the expected service | RPC endpoint baseline, service state, impersonation privilege minimization |
| Object Manager | Can an attacker pre-place a symbolic link/object before a privileged component creates it? | Project Zero object directory/path race, GreenPlasma 2026 | name resolution is trusted too much | object namespace telemetry, session object baselines, registry-link correlation |
| Handle/Object info | Can a low-privileged process learn addresses or duplicate useful handles? | DWM CVE-2026-20805, MSRC I/O Manager variant class | object metadata leaked or access checks were not forced | patching, handle query restrictions, KASLR-leak correlation |
| File/registry links | Can a privileged service write/delete through an attacker-controlled link? | PZ arbitrary file write class, CloudFiles/Defender-style reports, GreenPlasma | path checked before final object, link target changes later | reparse/link audit, privileged file-write baselines, minifilter telemetry |
| CLFS | Can attacker-controlled log-file data reach a kernel parser? | Microsoft CLFS CVE-2025-29824, CLFS HMAC mitigation | structured file parsed before strong authenticity | CLFS hardening, BLF creation telemetry, ransomware post-exploitation hunting |
| Named pipes | Can a service impersonate the wrong client or trust pipe traffic? | pipe-intercept, Potato-family lessons, Winsider service research | pipe ACL/identity/protocol assumptions | pipe ACL inventory, impersonation timing, pipe/process ancestry |
| CTF/DWM/desktop | Can a session or desktop transition activate a SYSTEM-context object? | GreenPlasma 2026, Project Zero CTF roots, DWM ALPC leak | desktop/session trust and object namespace interaction | Winlogon desktop events, CTF object baselines, ALPC/section leak patching |
| AD/service account object | Can directory object metadata imply privilege transfer? | BadSuccessor/dMSA 2025 | identity object relationship trusted too much | OU/dMSA permission audit, directory ACL review, DC patching |

## 1. COM And DCOM

Sources:

- https://arxiv.org/abs/2605.05000
- https://projectzero.google/2025/01/windows-bug-class-accessing-trapped-com.html
- https://0xc4r.github.io/posts/CVE-2026-21508/
- https://www.ibm.com/think/news/fileless-lateral-movement-trapped-com-objects
- https://attack.mitre.org/techniques/T1559/001/
- https://learn.microsoft.com/en-us/windows/win32/com/the-com-elevation-moniker

### Internals model

COM is activation + interface invocation + marshaling. When a client calls COM, the question is not only "which class?", but:

- who chooses the CLSID?
- does the class run in-process or out-of-process?
- which token does the server run under?
- does registry lookup use HKCU, HKLM, or the merged HKCR view?
- does activation policy differ from method authorization?
- is the object marshaled by value or by reference?
- do IDispatch or type libraries expose unexpected classes or interfaces?

### Abuse patterns

1. **Arbitrary or influenced CLSID creation.** If a privileged process lets a caller influence the CLSID or a registry indirection, the caller can force it to create a different object than the developer intended.
2. **HKCU/HKCR shadowing under impersonation.** If a service opens HKCR while impersonating a user, registry lookup can flow through that user's HKCU class hive.
3. **Trapped COM object.** An object is created in the server process while the client keeps a reference. If the object has a dangerous method or can load/execute logic, the action runs in the server context.
4. **Elevation moniker confusion.** Elevated COM is a supported feature, but a class or method that does not authorize the caller clearly becomes a confused deputy.
5. **COM race conditions.** COM services often run elevated and are reachable by authenticated users; state-machine races around file, registry, and object operations are a large surface.

### Public cases

- The SLYP paper, submitted May 6 2026, treats elevated COM services as a surface for race-condition LPE and reports 28 unknown vulnerabilities across nine COM services, with 16 CVEs acknowledged by MSRC.
- CVE-2026-21508 analyzes `WUDFHost.exe`, impersonation, HKCR/HKCU lookup, and arbitrary COM object initialization.
- Project Zero's 2025 trapped COM research describes a bug class where remoting technology lets a client reach unsafe objects inside a privileged server process.
- IBM's 2025 follow-up extends the same research line into fileless lateral-movement and detection framing.

### Why questions

1. Why is COM activation a security boundary, not only an object factory?
2. Why does HKCR's merged view make analysis easy to get wrong?
3. Why is impersonation during registry open different from impersonation during method invocation?
4. Why is by-reference marshaling more dangerous than by-value marshaling at a trust boundary?
5. Why does IDispatch widen the surface compared with strongly typed interfaces?
6. Why must elevated COM classes authorize each method?
7. Why is a SYSTEM COM service with a user-writable class path a serious bug?
8. Why must TreatAs, AppID, LocalServer32, and InProcServer32 be audited together?
9. Why do races in COM services often become LPE instead of only a crash?
10. Why should COM detection correlate registry queries, module loads, and server process ancestry?

## 2. RPC, ALPC, And Impersonation

Sources:

- https://securelist.com/phantomrpc-rpc-vulnerability/119428/
- https://learn.microsoft.com/en-us/windows/win32/rpc/rpc-start-page
- https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcimpersonateclient
- https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-security_quality_of_service
- https://github.com/silverf0x/RpcView
- https://github.com/tyranid/WindowsRpcClients

### Internals model

RPC has interface UUIDs, endpoints, protocol sequences, opnums, bindings, authentication, and impersonation. ALPC is the important local transport for `ncalrpc`. Abuse usually does not live in raw marshaling bytes alone; it lives in identity:

```text
client intent -> RPC runtime -> endpoint binding -> service method -> impersonation -> privileged action
```

### Abuse patterns

1. **Endpoint spoofing.** If a privileged client connects to a "service" but does not prove it is the real service, an attacker-controlled endpoint can become the receiver.
2. **Coercion into RPC call.** A privileged service is triggered into calling an endpoint that is unavailable or attacker-controlled.
3. **Impersonation privilege abuse.** `SeImpersonatePrivilege` appears in many service accounts; if an attacker gains an appropriate service context, receiving a connection or call from a stronger client can become a privilege bridge.
4. **IDL/marshaling bug.** RPC stub/unmarshal logic can create memory corruption, type confusion, out-of-bounds access, or authorization bugs.
5. **Connection-time vs call-time authorization drift.** A check during bind does not guarantee every later opnum is valid.

### Public cases

- Securelist PhantomRPC, published April 24 2026, describes an architectural weakness in Windows RPC: a process with impersonation privilege can escalate to SYSTEM or another high-privileged user through several paths; Microsoft had not released a patch at the time of publication.
- MS-RPC tooling such as RpcView, NtObjectManager/WindowsRpcClients, and MS-RPC-Fuzzer shows that modern research needs interface inventory, IDL recovery, opnum labeling, ETW, canaries, and replay discipline.

### Why questions

1. Why must RPC server identity be strongly bound, not inferred from endpoint name alone?
2. Why does `ncalrpc` being local not make it safe?
3. Why is `SeImpersonatePrivilege` almost "dangerous by design" in service contexts?
4. Why should UUIDs and opnums receive semantic names during audit?
5. Why can a disabled or unavailable service create spoofing opportunity?
6. Why must every RPC note record authentication level and impersonation level?
7. Why should an endpoint baseline include owner process, service state, and ACL?
8. Why must RPC fuzzing separate real server crashes from client marshalling failures?
9. Why do ALPC handle and section transfers change impact compared with named pipes?
10. Why should detection watch both endpoint registration and process/service lineage?

## 3. Object Manager Namespace

Sources:

- https://projectzero.google/2025/12/windows-exploitation-techniques.html
- https://googleprojectzero.blogspot.com/2018/08/windows-exploitation-tricks-exploiting.html
- https://blackfort-tec.de/en/insights/greenplasma-windows-ctf-injection-analysis
- https://www.microsoft.com/en-us/msrc/blog/2019/03/local-privilege-escalation-via-the-windows-i-o-manager-a-variant-finding-collaboration/

### Internals model

Object Manager manages named objects: directories, symbolic links, sections, events, mutexes, devices, ALPC ports, window-station/desktop-adjacent names, and session namespaces. Abuse revolves around one question:

```text
Which name does privileged code resolve, in which namespace, at what time, and with which root directory?
```

### Abuse patterns

1. **Object pre-creation.** The attacker creates an object or symlink before a privileged component creates an object with the same name.
2. **Symbolic link redirection.** Named object creation or open is redirected to another target in the namespace.
3. **Path lookup race widening.** The attacker slows name lookup to win a TOCTOU race between check and use.
4. **Shadow directory/hash collision reasoning.** Object directory lookup performance can be turned into a timing primitive.
5. **Section interception.** If a privileged component creates a section through a controlled name, handle or section side effects can become a primitive.

### Public cases

- Project Zero's 2025 update describes techniques for slowing Object Manager lookup to widen race windows on Windows 11 24H2.
- Project Zero's 2018 object directory work analyzes arbitrary object directory creation as an LPE class.
- Blackfort's 2026 GreenPlasma analysis describes Object Manager symlink abuse on a CTF session object plus registry-link abuse through CloudFiles policy structure. Treat this as "published stripped PoC / detection artifacts," not as a vendor-confirmed full exploit chain.
- MSRC's I/O Manager variant-finding post explains `RequestorMode`, `SL_FORCE_ACCESS_CHECK`, and `OBJ_FORCE_ACCESS_CHECK`, which matter whenever object open flows through kernel APIs.

### Why questions

1. Why can an object name be as much of an attack surface as a buffer?
2. Why is `\BaseNamedObjects` different from `\Sessions\<N>\BaseNamedObjects`?
3. Why can Object Manager symbolic links be more dangerous than normal file symlinks in some chains?
4. Why does create-before-privileged-create recur as a bug class?
5. Why can lookup latency widen a race window?
6. Why does a handle keep an object alive after its name disappears?
7. Why should privileged code use a root directory or private namespace where possible?
8. Why do session and desktop boundaries make object namespaces hard to audit?
9. Why is a section object a bridge between naming and memory?
10. Why does Object Manager detection need kernel visibility or specialized telemetry?

## 4. Handles, Access Checks, And Information Leaks

Sources:

- https://www.microsoft.com/en-us/msrc/blog/2019/03/local-privilege-escalation-via-the-windows-i-o-manager-a-variant-finding-collaboration/
- https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20805
- https://cvereports.com/reports/CVE-2026-20805

### Internals model

A handle is a mediated reference. An object pointer is a kernel address. Large bug classes appear when:

- privileged code returns handles or object metadata to a lower-privileged caller,
- an access check uses the wrong mode or flag,
- a system information API leaks addresses,
- handle duplication or inheritance crosses a trust boundary,
- object type indices or addresses become KASLR primitives.

### Abuse patterns

1. **KASLR/information leak.** An object, section, or port address leak does not immediately provide code execution, but it can make a memory corruption chain reliable.
2. **RequestorMode confusion.** A driver uses `Irp->RequestorMode` as a security decision while ignoring force-access-check flags.
3. **Handle lifetime confusion.** An object with no remaining name can still live because a handle or pointer reference exists.
4. **Wrong desired access.** A service grants an overly powerful handle and passes it to a caller.

### Public cases

- CVE-2026-20805: a DWM information disclosure related to ALPC port/section addresses, described as an ASLR/KASLR weakening primitive. The MSRC URL is canonical even if the page requires JavaScript.
- MSRC's 2019 I/O Manager variant class: drivers must consider both request mode and force-access-check paths.

### Why questions

1. Why is information disclosure often "stage 0" of an exploit chain?
2. Why must kernel object pointers be redacted from user-mode queries?
3. Why is `RequestorMode == KernelMode` not enough to trust the caller?
4. Why must a force-access-check flag propagate through every layer?
5. Why do inherited and duplicated handles matter in broker design?
6. Why should a report record the access mask, not only the handle value?
7. Why does object type index drift by build?
8. Why can a leaked section address increase exploit reliability?
9. Why does handle close not imply object destruction?
10. Why should defensive tooling baseline handle types by process role?

## 5. Registry And Configuration Manager

Sources:

- https://core-jmp.org/2026/05/eventvwr-uac-bypass-mscfile-hkcu-hijack/
- https://0xc4r.github.io/posts/CVE-2026-21508/
- https://blackfort-tec.de/en/insights/greenplasma-windows-ctf-injection-analysis
- https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry

### Internals model

The registry is a policy/configuration database, but in Windows exploitation it is often also a namespace and redirection surface:

- HKCR is a merged HKCU/HKLM view.
- HKCU class overrides can shadow machine-wide handlers.
- Predefined registry handles have caching and impersonation behavior.
- Some keys influence COM, shell behavior, services, tasks, policies, and file handlers.
- Registry links/REG_LINK or key redirection can turn a write/delete into policy tampering.

### Abuse patterns

1. **Per-user class hijack.** Privileged or auto-elevated code resolves a user-writable class handler.
2. **COM registry indirection.** Class metadata points to an unintended CLSID or path.
3. **Policy key redirection.** Link/key manipulation causes privileged code to read or write a different policy location.
4. **Service/task config mutation.** Weak ACLs or wrong ownership on service/task registry configuration becomes execution or persistence.

### Why questions

1. Why is HKCU shadowing HKLM both a feature and an exploit primitive?
2. Why is registry lookup under impersonation easy to misunderstand?
3. Why should COM and shell registry areas be audited together?
4. Why is a volatile registry link a stronger IOC than a single policy value?
5. Why does an auto-elevated binary plus HKCU handler create trust asymmetry?
6. Why does fast cleanup not remove event telemetry?
7. Why do service registry ACLs still matter when the binary path is not writable?
8. Why should per-user customization be constrained when a privileged broker reads it?
9. Why should registry writes be correlated with process integrity level?
10. Why does "by design" not mean "acceptable enterprise risk"?

## 6. Files, Reparse Points, Cloud Files, And Mini-Filters

Sources:

- https://projectzero.google/2025/01/windows-exploitation-tricks-trapping.html
- https://projectzero.google/2025/12/windows-exploitation-techniques.html
- https://blackfort-tec.de/en/insights/greenplasma-windows-ctf-injection-analysis
- https://www.microsoft.com/en-us/security/blog/2025/04/08/exploitation-of-clfs-zero-day-leads-to-ransomware-activity/
- https://support.microsoft.com/en-au/topic/common-log-file-system-clfs-authentication-mitigation-af903a7e-ceca-410e-a5bf-58b1c79e861d

### Internals model

Windows file operations pass through I/O Manager, file systems, filter drivers, and sometimes cloud placeholders. A path is not a stable object unless code safely opens the final object and binds later action to that handle.

### Abuse patterns

1. **TOCTOU path swap.** Code checks a path, then the attacker changes the target before use.
2. **Reparse/junction/symlink.** A privileged file operation follows an attacker-controlled link.
3. **Oplock/cloud callback timing.** The attacker slows an operation to win a race or trap memory/file access.
4. **False file immutability.** Code assumes file content or object identity cannot change after a check.
5. **Minifilter parser trust.** A kernel driver parses complex file/log state before authentication or hardening.

### Public cases

- Project Zero's 2025 memory-trap update highlights Windows 11 24H2 local SMB port behavior and Cloud Filter API behavior as timing/immutability research primitives.
- Microsoft CLFS CVE-2025-29824 was exploited after compromise for ransomware activity; Microsoft later documented CLFS authentication/HMAC mitigation for logfile integrity.
- 2026 Cloud Files Mini Filter Driver CVE reports exist, but many are patch-summary pages rather than deep primary research. Treat them as a watch list until vendor or researcher detail is available.

### Why questions

1. Why is a path string not object identity?
2. Why should privileged code act on a handle instead of a re-resolved path?
3. Why do oplocks and cloud callbacks make races more reliable?
4. Why must minifilters normalize reparse state carefully?
5. Why should CLFS use HMAC before parsing internal structures?
6. Why are parser bugs in a kernel log subsystem attractive to ransomware?
7. Why should file-operation telemetry include final path, reparse tag, and caller?
8. Why do `ProgramData` and per-user writable paths often appear in LPE?
9. Why do cloud placeholder features open new local LPE surfaces?
10. Why is a Patch Tuesday note not enough to understand the primitive?

## 7. Named Pipes And Service Accounts

Sources:

- https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipes
- https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
- https://learn.microsoft.com/en-us/windows/win32/ipc/impersonating-a-named-pipe-client
- https://windows-internals.com/faxing-your-way-to-system/
- https://github.com/gabriel-sztejnworcel/pipe-intercept

### Internals model

A named pipe is an IPC endpoint with a DACL and a message stream. A service can impersonate the client. This is why a named pipe is both a protocol surface and a token/identity surface.

### Abuse patterns

1. **Weak pipe ACL.** A low-privileged client can talk to a service that should not expose the pipe.
2. **Protocol trust.** A service trusts the message grammar more than caller identity.
3. **Impersonation timing bug.** A service parses or acts before correctly impersonating the client.
4. **Service-account bridge.** LocalService/NetworkService can have privileges such as `SeImpersonatePrivilege`; receiving a stronger token can become a bridge.

### Why questions

1. Why is a pipe ACL a security boundary?
2. Why must a server impersonate before opening a resource on behalf of a client?
3. Why does message replay/fuzzing need protocol state?
4. Why can a "low privilege" service account still hold dangerous privileges?
5. Why should pipe telemetry be tied to process ancestry?
6. Why can pipe MITM/interception easily distort timing?
7. Why must named pipes and RPC-over-named-pipe be distinguished?
8. Why can pipe instance count and races affect exploitability?

## 8. Token, Privilege, Service Hardening, And PPL

Sources:

- https://www.tiraniddo.dev/2020/01/empirically-assessing-windows-service.html
- https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens
- https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights
- https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-
- https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory

### Internals model

A token contains a user SID, group SIDs, privileges, integrity level, restricted/AppContainer state, and impersonation state. Service hardening adds service SIDs, per-service ACLs, and privilege trimming. PPL adds signer/protection hierarchy.

### Abuse patterns

1. **Privilege abuse.** `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`, `SeDebugPrivilege`, and `SeBackupPrivilege` are boundary-changing privileges.
2. **Confused deputy.** A privileged service acts for a caller but does not verify the caller tightly enough.
3. **PPL proxy/trust abuse.** The attack does not directly open a handle to a protected process; it abuses a trusted actor or signer hierarchy.
4. **Directory object identity abuse.** AD object attributes and ACLs can imply privilege transfer, as in BadSuccessor/dMSA.

### Why questions

1. Why can a service account outside Administrators still be dangerous?
2. Why is a privilege being enabled different from a privilege being present?
3. Why must impersonation level be recorded when analyzing RPC or pipes?
4. Why is PPL a trust hierarchy rather than only a flag?
5. Why does a service SID help hardening but not fix a logic bug?
6. Why is an AD object ACL an attack surface like a local object ACL?
7. Why does BadSuccessor belong to identity-object relationship abuse?
8. Why is token handle leakage often more important than token pointer leakage?
9. Why must least privilege audit both privileges and writable objects?
10. Why does every PPL bypass claim need build/HVCI/WDAC state?

## 9. Win32k, DWM, CTF, Desktops, And Sessions

Sources:

- https://blackfort-tec.de/en/insights/greenplasma-windows-ctf-injection-analysis
- https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20805
- https://cvereports.com/reports/CVE-2026-20805
- https://projectzero.google/2025/01/windows-exploitation-tricks-trapping.html
- https://learn.microsoft.com/en-us/windows/win32/winstation/window-stations

### Internals model

GUI/security surfaces include sessions, window stations, desktops, the Winlogon desktop, DWM, CTF/TSF, win32k kernel state, and user-mode brokers. Bugs often appear when the user desktop and secure desktop/SYSTEM desktop share, resemble, or can influence common objects, protocols, or state.

### Abuse patterns

1. **Desktop transition trigger.** UAC, lock, and logon desktops activate SYSTEM-context components.
2. **CTF object/protocol abuse.** Text Services Framework has a long research history because it must communicate across UI components.
3. **DWM information leak.** GUI brokers hold ALPC and section objects; leaks can weaken ASLR/KASLR.
4. **Win32k object lifetime/race.** GUI kernel objects have historically produced UAF, type confusion, and race issues.

### Why questions

1. Why does Session 0 isolation not solve every GUI boundary?
2. Why does the Winlogon desktop create SYSTEM-context objects that differ from the user desktop?
3. Why must CTF/TSF treat sender identity carefully?
4. Why can a DWM leak matter even without a write primitive?
5. Why does GUI kernel surface remain relevant after many mitigations?
6. Why must window station and desktop ACLs be in the threat model?
7. Why is a UAC prompt a desktop-transition event worth logging?
8. Why should CTF object baselines be per session?
9. Why does Win32k exploitability need a build and mitigation matrix?
10. Why is the display/input subsystem an indirect privilege boundary?

## 10. CLFS And Structured Kernel Parsers

Sources:

- https://www.microsoft.com/en-us/security/blog/2025/04/08/exploitation-of-clfs-zero-day-leads-to-ransomware-activity/
- https://support.microsoft.com/en-au/topic/common-log-file-system-clfs-authentication-mitigation-af903a7e-ceca-410e-a5bf-58b1c79e861d
- https://www.coresecurity.com/blog/cve-2026-2636-blf-log-file-unrecoverable-state-bsod

### Internals model

CLFS is a kernel-accessible logging subsystem. It parses `.blf` and log structures. Any kernel parser that reads a structured file from disk raises these questions:

```text
Is file data authenticated before parsing?
Which caller created or opened the file?
Which kernel context runs the parser?
```

### Abuse patterns

1. **Memory corruption from structured file.** Crafted log metadata causes the parser to corrupt kernel memory.
2. **Information leak prerequisite.** An exploit may need a kernel address leak before corruption becomes reliable.
3. **Post-compromise LPE.** Ransomware actors use CLFS LPE after initial foothold to gain privileged access.
4. **Parser hardening.** HMAC/authentication before parsing reduces the class "tampered file parsed as trusted structure."

### Why questions

1. Why is CLFS attractive to ransomware operators?
2. Why can a local kernel parser bug have large enterprise impact?
3. Why is authenticating a log file before parsing the right mitigation direction?
4. Why is a standard user being able to create input for a kernel parser a surface?
5. Why can a Windows 11 24H2 query restriction make an exploit fail even when the vulnerability remains?
6. Why is BLF creation telemetry useful for hunting?
7. Why does parser hardening carry compatibility cost?
8. Why may CLFS bug classes deserve higher patch priority than CVSS suggests?

## 11. Task Scheduler, WMI, SCM, BITS, And Helper Brokers

Sources:

- https://itm4n.github.io/hijacking-the-windows-marebackup-scheduled-task-for-privilege-escalation/
- https://windows-internals.com/printdemon-cve-2020-1048/
- https://attack.mitre.org/techniques/T1053/
- https://attack.mitre.org/techniques/T1047/

### Internals model

Scheduled tasks, WMI, SCM, BITS, the print spooler, and device association helpers are "privileged automation brokers." They exist to do work for users and administrators. Abuse appears when checks are client-side, path lookup is ambiguous, or ACLs allow more users to influence configuration than the developer expected.

### Abuse patterns

1. **Client-side validation only.** A UI validates a path, port, or action, but the server method does not.
2. **Executable/DLL search order.** A privileged task or service resolves a binary without a stable absolute path or safe search mode.
3. **Task/service config ACL.** A low-privileged user can modify configuration consumed by a privileged scheduler or service.
4. **WMI/COM broker chaining.** WMI or COM invokes a privileged operation that trusts caller-controlled parameters.

### Why questions

1. Why must broker APIs validate server-side?
2. Why are scheduled task XML/file ACLs not the whole security model?
3. Why can a rarely executed privileged helper be a good LPE target?
4. Why is WMI both a management plane and an attack surface?
5. Why must service start/stop rights be audited for non-admin users?
6. Why do binary search-order bugs still survive in the Windows ecosystem?
7. Why should telemetry include task registration/update, not only task execution?
8. Why is Print Spooler a recurring source of boundary bugs?

## 12. Device Objects, IOCTLs, And Driver Boundaries

Sources:

- [IOCTL reversing workflow](../userland-to-kernel/ioctl-reversing-workflow-deep-dive.md)
- [device ACL notes](../userland-to-kernel/device-acl-sddl-ioctl-access.md)
- https://www.microsoft.com/en-us/msrc/blog/2019/03/local-privilege-escalation-via-the-windows-i-o-manager-a-variant-finding-collaboration/

### Internals model

Driver exposure is Object Manager + I/O Manager + dispatch routine:

```text
\Device\Name / \DosDevices link
  -> security descriptor grants handle
  -> IOCTL access bits
  -> buffer method
  -> dispatch logic
  -> privileged primitive
```

### Abuse patterns

1. **Weak device ACL.** Everyone or Authenticated Users can open a device with write/execute-like IOCTL access.
2. **METHOD_NEITHER trust.** A driver dereferences user pointers without probe/capture/lifetime discipline.
3. **Physical memory/MSR primitive.** A hardware utility driver exposes too much.
4. **RequestorMode/check confusion.** A driver treats a kernel-origin IRP as trusted even when the user controls the path.
5. **BYOVD bridge.** A signed but vulnerable driver converts a local admin or low-privileged foothold into a kernel primitive, depending on ACL.

### Why questions

1. Why is the Device Object ACL first-line authorization?
2. Why must IOCTL access bits match operation risk?
3. Why is the buffer method a security-relevant design choice?
4. Why does METHOD_NEITHER require a capture/probe model?
5. Why does a signed driver not imply a safe driver?
6. Why is a physical memory primitive different from a virtual memory primitive?
7. Why does BYOVD detection start at driver load, not exploit behavior?
8. Why should Driver Verifier, SDV, or CodeQL map bug classes first?

## 13. Memory Manager, Sections, I/O Rings, And Data-Only Primitives

Sources:

- https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/
- [page table deep dive](../windows-internals/page-table-and-address-translation-deep-dive.md)
- [I/O ring notes](io-ring-research-notes.md)

### Internals model

Modern Windows exploitation often avoids direct control-flow hijack because of KCFG, HVCI, CET, and PatchGuard. Data-only primitives change kernel-owned data so the kernel performs useful work for the attacker.

### Abuse patterns

1. **Section/shared memory confusion.** The same bytes are visible across a trust boundary under wrong assumptions.
2. **I/O ring object manipulation.** An existing kernel object can be steered into a read/write primitive if the attacker already has a weak write.
3. **Page table/PTE manipulation.** Translation and permission state become the primitive.
4. **KASLR leak + data-only write.** A leak turns a weak write into a build-specific reliable chain.

### Why questions

1. Why does arbitrary write not require code execution if the target data is powerful enough?
2. Why did I/O rings become a post-exploitation primitive on Windows 11?
3. Why do KCFG, HVCI, and CET push attackers toward data-only techniques?
4. Why is a section object both IPC and a memory manager object?
5. Why are PTE bits security policy?
6. Why does kernel object layout drift break exploit chains?
7. Why is a data-only primitive harder to detect than shellcode?
8. Why must mitigation notes include build and VBS state?

## 14. Identity, AD Objects, Netlogon, SMB, And NTLM Coercion

Sources:

- https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory
- https://www.akamai.com/blog/security-research/badsuccessor-is-dead-analyzing-badsuccessor-patch
- https://attack.mitre.org/techniques/T1187/
- https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview

### Internals model

Windows enterprise identity is also object security: AD objects, attributes, ACLs, service accounts, Kerberos tickets, NTLM challenges, SMB signing, and delegation. Abuse is often "metadata says the caller may act as someone else."

### Abuse patterns

1. **Directory object relationship abuse.** An attribute/ACL relationship implies privilege transfer.
2. **Delegation confusion.** A service account or machine account can act for a user under conditions the administrator did not intend.
3. **NTLM coercion.** A shell/protocol handler or SMB path causes outbound authentication to an attacker-controlled endpoint.
4. **Netlogon/RPC trust.** Domain protocols have severe blast radius when authentication or packet parsing fails.

### Public cases

- BadSuccessor 2025 abused dMSA, a Windows Server 2025 feature, to escalate in AD; Akamai reported that many environments had non-admin users with relevant permissions.
- Post-patch analysis says the direct path changed, but dMSA remains a credential/privilege acquisition primitive in already-owned domains.
- Core-jmp/Search URI/Snipping Tool-style NTLM notes belong in this bucket as protocol-handler coercion, not endpoint RCE.

### Why questions

1. Why is an AD object ACL a privilege boundary?
2. Why can "can create service account object" imply much more than object creation?
3. Why do Kerberos delegation bugs have domain-wide blast radius?
4. Why is an NTLM leak dangerous without a plaintext password?
5. Why should outbound SMB/WebDAV be egress-controlled?
6. Why does DC patch priority differ from workstation patch priority?
7. Why do identity bugs often look like feature abuse?
8. Why must detection include directory changes, not only endpoint process events?

## Google/Search Workflow

Use these query shapes to keep research systematic:

```text
site:projectzero.google Windows "<subsystem>" "privilege escalation"
site:securelist.com Windows RPC ALPC impersonation privilege escalation 2026
site:msrc.microsoft.com/update-guide/vulnerability "Windows <component>" "Elevation of Privilege"
"Windows" "<component>" "ALPC" "EoP" "2026"
"Windows" "COM" "race condition" "MSRC" "2026"
"Object Manager" "symbolic link" "Windows" "privilege escalation"
"Cloud Files Mini Filter Driver" "Elevation of Privilege" "2026"
"CLFS" "ransomware" "elevation of privilege" "Microsoft" "2025"
"dMSA" "Windows Server 2025" "privilege escalation" "Akamai"
```

When a result appears, classify it before deep reading:

| Trust | Treatment |
|---|---|
| Microsoft/MSRC/CISA/vendor advisory | canonical for affected product, severity, patch status |
| Researcher/vendor technical post | good for primitive and root cause, verify claims |
| arXiv/preprint | good research direction, mark as preprint unless peer reviewed |
| GitHub PoC | never import recipe; extract claims, affected build, telemetry |
| News/AI summary/forum | use only as pointer to primary sources |

## Research Template

Use this template for every new Windows Internals abuse note:

```text
Subsystem:
Windows Internals concept:
Boundary:
Who is low privilege:
Who is high privilege:
Object/path/handle/token involved:
Primitive:
Preconditions:
Public case:
What invariant broke:
Why the design existed:
Why it became unsafe:
Mitigations:
Telemetry:
Build/version notes:
Questions still open:
Safety cuts:
```

## Next Documents To Split Out

1. `com-dcom-abuse-and-detection-atlas.md`
2. `object-manager-symlink-and-namespace-abuse.md`
3. `rpc-alpc-impersonation-and-endpoint-spoofing.md`
4. `windows-file-link-cloudfiles-clfs-abuse.md`
5. `ctf-dwm-desktop-session-boundary-notes.md`
6. `windows-identity-object-abuse-ad-dmsa-ntlm.md`

# Source Reading Notes 2026-06-05

Backlinks: [topic index](topic-index.md) | [master map](master-driver-research-map.md) | [deep notes](source-deep-notes-2026-06-05.md) | [core-jmp deep notes](core-jmp-deep-notes-2026-06-05.md) | [patch diff workflow](../kernel-research/patch-diff-and-binary-comparison-workflow-er-notes.md)

## Purpose

Ghi chú này tóm tắt các nguồn mới do người dùng đưa vào ngày 2026-06-05. Mục tiêu là học cách đọc, phân loại primitive, dựng lab và kiểm chứng claim; không nhập payload, lệnh bypass, shellcode, C2, AMSI/EDR bypass recipe hoặc trigger exploit.

For the expanded explanation and "why" question bank, see [source deep notes](source-deep-notes-2026-06-05.md). For the dedicated core-jmp pass, see [core-jmp deep notes](core-jmp-deep-notes-2026-06-05.md).

Rule đọc an toàn:

```text
source -> claim -> primitive / invariant -> precondition -> telemetry -> mitigation -> lab-safe question
```

## Add To Study Queue

| Source | Nên học gì | Cách đọc trong repo |
|---|---|---|
| `pipe-intercept` | Named pipe traffic có thể được proxy để quan sát protocol IPC; tool dùng pipe client/server proxy rồi bridge sang WebSocket/HTTP proxy. | Bổ sung cho `windows-ipc-boundary-atlas.md`: tập trung vào ACL, identity, impersonation, pipe instance ordering, client/server trust. |
| Windows Internals, dynamic analysis | Quy trình organic: bật mitigation, chạy WinDbg, quan sát exception, dùng IDA để nối runtime behavior với code path. | Bổ sung cho WinDbg workflow: ghi lại giả thuyết sau mỗi breakpoint, rồi quay lại static analysis để đặt tên structure/function. |
| `post-patch-postmortem` + UUP dump workflow | Pipeline patch-diff thực dụng: liệt kê binary versions, tải package, trích binary, tạo BinExport/BinDiff, dựng VM đúng build cũ. | Bổ sung cho patch-diff workflow: LLM chỉ là assistant đọc diff, không là nguồn chân lý. |
| Kernullist kernel segment heap | Kernel pool hiện đại sau Windows 10 19H1: segment heap, kLFH/VS allocator, metadata encoding, secure pool/KDP pressure. | Bổ sung cho `kernel-pool-exploitation-study-map.md`; tránh copy offset và exploit-recovery recipe. |
| Quarkslab IUM debugging | VSM/VTL/IUM mental model: VTL0 không đọc được VTL1; debug Trustlet cần hiểu hypervisor, Secure Kernel và page walk. | Bổ sung cho HVCI/VBS và hypervisor-assisted introspection notes. |
| Core-jmp Windows/Search/IPC/RPC posts | Nhiều bài là rewrite/tổng hợp nguồn khác; tốt để tìm link gốc, nhưng nên đọc primary source trước. | Dùng như source map, không coi là authority nếu có upstream research link. |

## Skip Or Treat As Secondary

| Source | Lý do |
|---|---|
| Core-jmp BYOVD/PPL/callback posts | Repo đã có BYOVD, callback tamper, PPL, PatchGuard/HVCI notes. Chỉ lấy thêm reference nếu có primary source mới. |
| Core-jmp EDR/AMSI/process-injection posts | Quá operational. Chỉ ghi detection model: API/ETW/registry/process ancestry/memory-permission transitions. |
| PositiveIntent | Evasive loader. Không nhập usage/feature recipe. Chỉ dùng để hiểu detection pressure quanh .NET loader, ETW/AMSI, entropy, resource embedding, host binding. |
| staged-DLL-Injection-SMB | Operational injection/C2 staging PoC. Không nhập build steps. Chỉ dùng làm detection checklist cho remote thread, SMB DLL load, suspicious module path, child thread start. |
| Codeby Defender/AMSI guide | Operational defense-evasion guide. Chỉ dùng phần kiến trúc Defender/AMSI/ETW/AppLocker ở mức defensive. |
| WhiteKnight anti-cheat vs EDR bypass | Có code/technique examples. Giữ ở mức comparison: anti-cheat và EDR cùng quan tâm injection/hooking, nhưng threat model khác. |

## Patch-Diff Workflow Quality Gates

Nguồn chính:

- https://github.com/joshterrill/post-patch-postmortem
- https://uupdump.net/
- User-provided workflow from Josh Terrill social post, mirrored by trend indexes.

Workflow dễ hiểu:

```text
pick binary, e.g. tcpip.sys
  -> enumerate versions and patch packages
  -> produce old/new disassembly and BinDiff
  -> ask LLM for hypotheses about changed checks, types, and bounds
  -> map binary version to exact Windows build
  -> build old VM and fixed VM
  -> verify every LLM claim manually in IDA/Ghidra/WinDbg
  -> write a non-operational root-cause note
```

Quality gates:

1. Never accept an LLM explanation until the changed basic blocks, call graph and data-flow are manually checked.
2. Record exact file version, SHA-256, PDB GUID/age, Windows build, KB and symbol path.
3. Separate "patch changed this code" from "this was the vulnerability"; the diff may include refactors and hardening unrelated to the CVE.
4. Test both old and new builds when possible. A one-build crash is weak evidence.
5. Keep exploitability notes at primitive level: bounds check, refcount, lifetime, type confusion, info leak, policy bypass.

## Core-jmp Windows Catalog

Core-jmp had 121 unique posts across the paginated archive at review time. Relevant Windows/kernel/reversing items:

| Core-jmp post | Upstream / referenced source | Takeaway |
|---|---|---|
| Eventvwr UAC bypass via `mscfile` HKCU hijack | LOLBAS Eventvwr, Enigma0x3, MITRE T1548.002, Sysmon | Classic auto-elevation registry-hijack pattern. Learn detection: user-writable class handler changes, unexpected `eventvwr.exe` child process, high-integrity child ancestry. Do not copy payload steps. |
| Hooking Windows Named Pipes | Synacktiv `thats_no_pipe`, Microsoft Named Pipes docs, `pipe-intercept` | Named pipes are IPC endpoints with ACL/identity/instance-ordering subtleties. Research value is protocol visibility and trust-boundary review. |
| No More Hardcoded Kernel Offsets | S12Deff PDB dynamic offset post | Already covered by runtime PDB notes. Use as reminder: offset-free research still needs symbol validation and build matrix. |
| `gdrv3.sys` hardware primitives | Zonifer writeup, LOLDrivers | Already covered by BYOVD primitive taxonomy. Useful as another driver-family example for physical memory, MSR and hardware access classification. |
| Enumerating process creation callbacks | S12Deff callback enumeration | Already covered by callback-surface and callback-tamper docs. Use defensively for cross-view callback inventory. |
| Kernel Karnage callback patching | NVISO Kernel Karnage | Operational if copied directly. Keep only the lesson: callbacks are high-value detection choke points; defenders should monitor registration, unexpected callback loss and kernel memory tamper signals. |
| Windows Search URI NTLM coercion | Huntress Windows Search URI handler post, Geoff Chappell ExplorerFrame notes | New userland/IPC-ish track: URI handlers can cross trust boundaries and coerce outbound authentication. Detection: unusual protocol invocation, SMB/WebDAV auth attempts after link open, shell handler ancestry. |
| Vanguard guarded regions | reversing.info Xyrem post | Anti-cheat kernel design intersects with page tables, CR3 switching and scheduler context. Study as memory-isolation pattern, not cheat bypass. |
| Early boot mitigation config | ERNW CmControlVector research | Good source for system mitigation provenance: registry/control-vector values copied early into kernel globals, later affecting process mitigation behavior. |
| BYOVD attack surface certificate abuse | GhostWolfLab | Repo already has BYOVD source map. New angle: certificate/signing trust can become the primitive, not just a vulnerable IOCTL. |
| DIY EDR from scratch | WhiteFlag blog, Microsoft WDK samples | Good defensive learning: callbacks, user-mode hooks and injection detection as a minimal EDR architecture. |
| Automating MS-RPC vulnerability research | Incendium/XPN, NtObjectManager, RpcView, RPCMon | Add to IPC research: enumerate RPC interfaces, generate clients, fuzz structures, correlate ETW/ProcMon/crash signals. |
| Recursive MS-RPC fuzzing with ETW | MS-RPC-Fuzzer, Incendium | Strong workflow source: recursive structure generation, union handling, canary tracing, replay and ETW-backed triage. |
| Windows kernel driver OOB | WhiteKnightLabs OOB article | Already broadly covered by IOCTL bug-class playbook; useful as a teaching source for bounds/integer/length validation. |
| Win32k async type confusion | s4dbrd CVE-2026-20811 post, MSRC | Fits existing Win32k track: GUI object lifetime, feature flags, async action path, patch diff and crash confirmation. |
| Virtual memory fundamentals | Melatoni blog | Already covered by page-table docs; useful as primer for students before kernel page-table walking. |

## User-Submitted Sources

### `pipe-intercept`

Source: https://github.com/gabriel-sztejnworcel/pipe-intercept

The tool proxies Windows named-pipe communication by creating pipe-side proxy instances and bridging traffic into an HTTP-proxy-friendly WebSocket path. The useful concept is not "how to intercept anything", but how pipe clients decide which pipe instance to connect to, how pipe server permissions affect interception, and how process identity checks can break proxying.

Defensive questions:

- Does the pipe DACL allow unexpected users or network clients?
- Does the server authenticate the client using impersonation or a protocol-level handshake?
- Can a fake/early pipe instance change client behavior?
- Are pipe messages length-prefixed, authenticated and versioned?

### Windows Internals Dynamic Analysis

Source: https://windows-internals.com/an-exercise-in-dynamic-analysis/

Yarden Shafir's post is a good model for dynamic analysis discipline. It starts with an observed guard-page exception in a protected process, maps the faulting address back to a PE section/export table, identifies PayloadRestrictions behavior, then uses static analysis to find the vectored exception handler and reason about guard-page reset via single-step.

Practical lesson:

```text
observe exception
  -> identify memory region and module
  -> hypothesize owning component
  -> find registration point
  -> break on handler
  -> rename state as evidence accumulates
```

### Kernullist Kernel Segment Heap

Source: https://kernullist.github.io/kernullist-blog/posts/kernel-segment-heap/

The post is valuable because it explains why older pool-exploitation instincts fail on modern Windows. Legacy NT pool had inline plaintext metadata, predictable adjacency and easy pool walking. Kernel segment heap moves and encodes metadata, separates allocator contexts and pushes exploitation toward precise object pairing, leaks and build-specific allocator understanding.

Repo integration target:

- Add a future section to `docs/windows-heap/kernel-pool-exploitation-study-map.md`.
- Cross-link with HVCI/VBS/KDP notes for secure pool and hypervisor-enforced write protection.

### Quarkslab IUM Debugging

Source: https://blog.quarkslab.com/debugging-windows-isolated-user-mode-ium-processes.html

This is a high-value VBS/VTL research source. It explains that IUM Trustlets run in VTL1, where normal VTL0 user/kernel debuggers cannot attach. The article uses nested virtualization and hypervisor debugging to reason from `HvCallVtlReturn` to Secure Kernel context, then uses VMCS/CR3/page-walk reasoning to locate VTL1 state.

Lab-safe takeaway:

- Learn the VTL model and why ring 0 is not "the whole machine" under VBS.
- Record build-specific hypervisor/Secure Kernel assumptions.
- Do not treat VTL1 debugging patches as normal test workflow on production systems.

### PositiveIntent / staged DLL Injection / Codeby Defender-AMSI

Sources:

- https://github.com/depthsecurity/PositiveIntent
- https://github.com/kasturixbm5/staged-DLL-Injection-SMB-
- https://codeby.net/threads/obkhod-windows-defender-i-amsi-prakticheskii-gaid-po-defense-evasion-dlya-red-team.92763/

These sources are too operational to import as technique docs. Keep only detection concepts:

- .NET loader activity, suspicious resource-packed assemblies, unusual entropy shaping.
- AMSI/ETW tamper indicators and missing telemetry families.
- Remote-thread/module-load patterns.
- SMB-sourced DLL paths and unexpected module loads from remote shares.
- AppLocker/LOLBAS abuse as policy-bypass pressure, not as a recipe.

### WhiteKnightLabs Anti-Cheat vs EDR

Source: https://whiteknightlabs.com/2024/02/09/a-technical-deep-dive-comparing-anti-cheat-bypass-and-edr-bypass/

Useful mental model: anti-cheat and EDR both monitor process/memory behavior, but they optimize for different outcomes. Anti-cheat protects game integrity and fairness; EDR protects enterprise systems and forensic visibility. Shared technical surfaces include injection, hooks, memory scanning, process creation, handle access and kernel drivers. Treat overlapping terms carefully because "bypass" has different legal and ethical contexts in each ecosystem.

## Suggested Follow-Up Docs

1. `docs/userland-to-kernel/named-pipe-interception-and-ipc-trust.md`
2. `docs/kernel-research/windows-patch-diff-llm-workflow.md`
3. `docs/windows-heap/kernel-segment-heap-modern-pool-notes.md`
4. `docs/kernel-research/ms-rpc-fuzzing-and-etw-triage.md`
5. `docs/mitigations/vsm-ium-debugging-source-map.md`

The first pass should be source maps and study questions only. Deep dives should be added only after reading primary sources and removing operational exploit content.

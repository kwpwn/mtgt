# Source Deep Notes 2026-06-05

Backlinks: [source reading notes](source-reading-notes-2026-06-05.md) | [core-jmp deep notes](core-jmp-deep-notes-2026-06-05.md) | [topic index](topic-index.md) | [master map](master-driver-research-map.md)

## Purpose

Day la ban ghi chi tiet hon cho cac blog/source queue ngay 2026-06-05. Moi muc di theo format:

```text
doc nay noi gi
  -> co che hoat dong
  -> vi sao thiet ke nhu vay
  -> vi sao thanh attack surface
  -> cach kiem chung an toan
  -> cau hoi "vi sao"
```

Khong nhap payload, trigger, command chain, C2, shellcode, AMSI/EDR bypass recipe hoac exploit step-by-step.

Core-jmp co nhieu bai Windows/kernel/RE rieng, nen phan do duoc tach thanh [core-jmp deep notes](core-jmp-deep-notes-2026-06-05.md) de de doc ky tung post.

## 1. Named Pipes va `pipe-intercept`

Sources:

- https://github.com/gabriel-sztejnworcel/pipe-intercept
- https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipes
- https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
- https://learn.microsoft.com/en-us/windows/win32/ipc/impersonating-a-named-pipe-client
- https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-instances
- https://core-jmp.org/2026/04/hooking-windows-named-pipes/
- https://www.synacktiv.com/en/publications/hooking-windows-named-pipes

### Explain

Named pipe la mot IPC endpoint co ten trong Windows. Server tao pipe, client ket noi bang ten pipe, hai ben doc/ghi message hoac byte stream. Microsoft docs nhan manh hai diem can nho:

- Pipe co security descriptor, nen viec ket noi va tao instance phu thuoc DACL.
- Server co the impersonate client, tuc thread server tam thoi chay voi security context cua client.

`pipe-intercept` bien pipe traffic thanh luong co the quan sat qua HTTP proxy. Concept cua no:

```text
target client
  -> proxy pipe instance
  -> websocket bridge
  -> HTTP proxy view
  -> real pipe server
```

Dieu hay cua tool khong nam o "chay tool", ma nam o viec no buoc minh hieu cach client chon pipe instance. Theo README, proxy khong magic hook kernel; no tao pipe server instance rieng. Neu target server da tao instance truoc, client dau tien co the van vao instance that. Neu app dung `FILE_FLAG_FIRST_PIPE_INSTANCE`, proxy tao instance sai thoi diem co the lam server that fail.

### Why It Works

Named pipe cho phep nhieu instance cung ten. He thong noi client den mot instance dang doi ket noi. Neu attacker/researcher co quyen tao instance cung ten, ho co the chen mot diem quan sat vao luong client-server.

Tai sao Windows cho nhieu instance cung ten? De server xu ly nhieu client dong thoi. Neu chi co mot instance, server phai xu ly client theo hang doi, hieu nang kem. Nhieu instance la feature dung, nhung feature nay tao ra cau hoi security: ai duoc tao instance, ai duoc ket noi, instance nao duoc client gap truoc.

### Attack Surface

Named pipe nguy hiem khi app coi pipe name la identity. Pipe name chi la dia chi endpoint, khong phai bang chung server dung. Neu client khong xac thuc server, proxy/fake server co the nhin thay protocol. Neu server khong impersonate dung cach, request cua client co the duoc xu ly bang quyen server cao hon.

### Defensive Model

Can kiem:

- DACL cua pipe co qua rong khong.
- Co cho `Everyone`, `Anonymous`, network users, cross-session users khong.
- Client co verify server PID, SID, service identity hoac challenge/response khong.
- Server co impersonate client truoc khi cham tai nguyen nhay cam khong.
- Message co length, version, auth, replay protection khong.
- Co pipe nao expose remote qua SMB pipe namespace khong.

### Why Questions

1. Vi sao pipe name khong du de xac thuc server?
2. Vi sao default DACL cua pipe co the nguy hiem voi service chay SYSTEM?
3. Vi sao `GENERIC_WRITE` tren pipe co the lien quan den quyen tao pipe instance?
4. Vi sao nhieu pipe instance la yeu cau hieu nang nhung lai tao race/ordering problem?
5. Vi sao client dau tien co the vao server that, con client sau moi vao proxy?
6. Vi sao `FILE_FLAG_FIRST_PIPE_INSTANCE` lam interception bang fake instance kho hon?
7. Vi sao impersonation phai duoc dat dung impersonation level?
8. Vi sao server nen `RevertToSelf` sau khi impersonate?
9. Vi sao protocol tren pipe van can auth rieng neu pipe DACL da co?
10. Vi sao named pipe hay xuat hien trong RPC, service control, EDR/AV agent, Docker, update service?
11. Vi sao pipe fuzzing can biet message boundary thay vi chi mutate byte stream?
12. Vi sao defender nen log pipe server process, client process va DACL cung luc?

## 2. Windows Internals Dynamic Analysis: PayloadRestrictions/EAF

Source:

- https://windows-internals.com/an-exercise-in-dynamic-analysis/

### Explain

Yarden Shafir phan tich Export Address Filtering cua Windows Defender Exploit Guard. Bai nay hay vi no khong bat dau bang "toi biet dap an"; no bat dau bang mot exception.

Dong suy luan:

```text
enable mitigation
  -> run target under WinDbg
  -> observe guard page violation
  -> map fault address to module/section
  -> notice export table access
  -> infer PayloadRestrictions owns behavior
  -> find vectored exception handler in IDA
  -> connect guard-page exception and single-step exception
```

EAF dung PAGE_GUARD de bien viec cham vao export table thanh tin hieu. Khi co code doc export table, CPU/OS raise guard-page exception. Mitigation handler xem ai doc, dia chi nao bi doc, co hop le khong. Sau do no dung trap flag/single-step de dat lai guard page sau instruction tiep theo. Neu khong dat lai, PAGE_GUARD chi trigger mot lan.

### Why It Works

Export table la noi malware/shellcode hay quet de resolve API ma khong can import table ro rang. EAF khong cam moi access; no dat "tripwire" len page chua export data. Guard page la co che san co cua virtual memory, nen mitigation co the quan sat access ma khong can rewrite moi ham export.

### Research Method Lesson

Quan trong nhat la cach dat ten bien/structure. Tac gia khong doi co full symbol. Ho dung:

- `!address` de biet fault address thuoc image nao.
- PE header/export directory de biet offset co y nghia gi.
- IDA de tim handler dang ky bang API exception.
- WinDbg memory dump de dat ten mang/module/region.

Noi cach khac: static analysis dat gia thuyet, dynamic analysis chung minh hoac bac bo.

### Why Questions

1. Vi sao guard page phu hop de bat memory access hon la hook tung API?
2. Vi sao guard page chi trigger mot lan neu khong dat lai?
3. Vi sao mitigation can single-step exception sau guard-page exception?
4. Vi sao export table la surface co y nghia voi shellcode/manual API resolution?
5. Vi sao fault address phai duoc map ve PE directory truoc khi doc disassembly?
6. Vi sao khong nen dat ten structure qua som khi chua co runtime evidence?
7. Vi sao vectored exception handler la cho can tim khi thay exception lap lai?
8. Vi sao PAGE_GUARD khong dong nghia exploit, ma co the la mitigation behavior binh thuong?
9. Vi sao dynamic analysis nen ghi lai "what I know" va "what I assume" rieng?
10. Vi sao mot mitigation user-mode DLL van co the tao behavior giong anti-debug?

## 3. Patch-Diff + LLM + UUP Dump Workflow

Sources:

- https://github.com/joshterrill/post-patch-postmortem
- https://uupdump.net/
- Social workflow by Josh Terrill, mirrored in trend indexes.
- Existing repo: [patch diff workflow](../kernel-research/patch-diff-and-binary-comparison-workflow-er-notes.md)

### Explain

Workflow nguoi dung dua vao rat tot:

```text
pick binary, e.g. tcpip.sys
  -> use post-patch-postmortem to list versions / diff packages
  -> generate BinExport and BinDiff
  -> ask LLM to explain changed functions
  -> map old binary to exact Windows build via UUP dump
  -> create matching VM
  -> write tests backward from hypotheses
```

Gia tri cua `post-patch-postmortem`: no giam phan viec lap lai cua Patch Tuesday research. Thay vi tu tim KB, tai MSU/CAB, extract binary, tao diff, tool gom cac buoc nay thanh workflow hep: list target va diff target. UUP dump giup dung dung build cu de test behavior, khong chi doc diff tren binary.

### Where LLM Helps

LLM tot o:

- tom tat changed functions,
- de xuat ten bien/structure tam thoi,
- nhom diff thanh "bounds check", "type check", "refcount", "lifetime", "policy check",
- viet danh sach hypothesis can verify.

LLM khong duoc coi la source of truth. No co the nham function purpose, nham calling convention, nham invariant, hoac bo qua compiler noise.

### Quality Gates

Can ghi moi lan:

- binary name,
- old/new file version,
- SHA-256,
- PDB GUID/age,
- KB,
- Windows build,
- architecture,
- tool versions,
- symbol path,
- BinDiff similarity/confidence.

### Why Questions

1. Vi sao diff patch khong tu dong noi cho ta biet vulnerability?
2. Vi sao function changed co the chi la refactor hoac hardening phu?
3. Vi sao phai dung dung Windows build cu thay vi "gan gan cung version"?
4. Vi sao PDB GUID/age quan trong hon moi file name?
5. Vi sao LLM nen output hypotheses, khong output ket luan?
6. Vi sao can so sanh old VM va fixed VM?
7. Vi sao crash tren old build chua du de chung minh root cause?
8. Vi sao compiler optimization co the lam BinDiff misleading?
9. Vi sao network stack target nhu `tcpip.sys` can packet capture, ETW va kernel debugging cung luc?
10. Vi sao "working backwards from LLM analysis" phai co manual breakpoint/decompiler proof?
11. Vi sao patch-diff note nen ghi "changed invariant" thay vi "exploit steps"?
12. Vi sao build provenance la phan cua exploitability?

## 4. Eventvwr UAC Bypass: Read As Detection Case

Sources:

- https://core-jmp.org/2026/05/eventvwr-uac-bypass-mscfile-hkcu-hijack/
- https://lolbas-project.github.io/lolbas/Binaries/Eventvwr/
- https://attack.mitre.org/techniques/T1548/002/
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works?link_from_packtlink=yes
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/architecture

### Explain

Core idea: UAC tach administrator thanh hai token: standard token va elevated admin token. App binh thuong chay standard token. Khi app can admin token, Windows dung elevation flow. Mot so Windows-signed administrative tools co auto-elevation behavior tuy policy/build. Event Viewer mo `.msc` console qua file association. Neu lookup file association uu tien user hive truoc machine hive, thi user-writable handler co the anh huong chuoi mo file.

Day la ly do technique nay la UAC bypass, khong phai kernel LPE:

```text
medium-integrity admin user
  -> abuses trusted auto-elevated binary behavior
  -> high-integrity child/action
```

No can user da co admin approval mode context. No khong bien standard domain user thanh admin that su.

### Why It Works

Windows co per-user class registration de app/user tuy bien file association ma khong can admin. Day la feature hop ly. UAC co auto-elevated Windows tools de UX khong qua phien. Khi hai feature gap nhau, user-controlled class handler co the anh huong elevated tool neu tool lookup khong pin system handler.

### Defensive Model

Doc bai nay nhu IOC/detection case:

- registry write vao user class handler nhay cam,
- Event Viewer co child process bat thuong,
- high-integrity child co parent la auto-elevated binary,
- short-lived registry key create/delete,
- Sysmon registry set/process creation correlation.

### Why Questions

1. Vi sao UAC khong phai security boundary manh nhu kernel boundary?
2. Vi sao admin approval mode tao split token?
3. Vi sao child process thuong inherit token cua parent?
4. Vi sao auto-elevated Windows binary ton tai?
5. Vi sao per-user class registration uu tien hon machine-wide class registration?
6. Vi sao user-writable registry path co the tac dong elevated process?
7. Vi sao setting UAC "Always Notify" lam nhieu auto-elevation abuse kem gia tri hon?
8. Vi sao detection nen nhin parent-child ancestry, khong chi registry key?
9. Vi sao attacker hay cleanup key ngay sau trigger?
10. Vi sao cleanup nhanh van de lai event sequence neu telemetry du tot?
11. Vi sao `eventvwr.exe -> mmc.exe` co the binh thuong, nhung `eventvwr.exe -> script/interpreter` dang nghi?
12. Vi sao enterprise nen treat UAC bypass as post-compromise signal?

## 5. Kernullist Kernel Segment Heap

Source:

- https://kernullist.github.io/kernullist-blog/posts/kernel-segment-heap/

### Explain

Bai nay giai thich su dich chuyen tu legacy NT pool sang kernel segment heap. Legacy pool co `_POOL_HEADER` inline ngay truoc user data. Metadata gan data lam pool overflow co the de dang cham metadata chunk ke ben. Segment heap thay doi dieu do bang:

- allocator context rieng theo pool type,
- kLFH cho size nho,
- VS allocator cho variable-size chunks,
- metadata duoc encode bang key va self address,
- dynamic lookaside/delay-free lam timing UAF kho hon,
- ExAllocatePool2 zero-init by default,
- ExAllocatePool3 ho tro Secure Pool/KDP.

### Why It Matters

Nhieu exploit cu dua tren assumption:

```text
object A next to object B
  -> overflow A
  -> corrupt B header or pointer
  -> free path gives primitive
```

Segment heap lam assumption nay yeu di. Khong phai overflow het gia tri, nhung phai co:

- dung bucket/size class,
- target object co truong co y nghia,
- allocation groom trigger duoc,
- leak de decode metadata hoac tim self-address,
- crash-recovery/failure-mode reasoning.

### Defensive/Research Model

Voi crash pool hien dai, dung hoi "offset nao ghi vao dau?" truoc. Hay hoi:

```text
allocator path?
pool type?
size bucket?
LFH active?
VS or segment backend?
metadata encoded?
object target controlled by user?
build-specific keys/symbols?
```

### Why Questions

1. Vi sao inline plaintext pool header la weakness?
2. Vi sao metadata isolation lam pool walking cu bi hong?
3. Vi sao NonPagedPoolNx va PagedPool tach heap instance lai quan trong?
4. Vi sao size class/bucket match la bat buoc trong kLFH exploitation reasoning?
5. Vi sao random placement khong xoa bug, chi lam exploitability kho hon?
6. Vi sao header encoding can chunk address hoac heap key de decode?
7. Vi sao delay-free pha vo assumption "free xong reclaim ngay"?
8. Vi sao ExAllocatePool2 zero-init by default giam info leak?
9. Vi sao Secure Pool/KDP dua mot phan data protection sang VTL1/hypervisor?
10. Vi sao VTL0 kernel write primitive co the van khong sua duoc Secure Pool?
11. Vi sao pool exploit writeup phai ghi build va allocator path?
12. Vi sao old HEVD-style pool lessons van huu ich nhung khong du cho 19H1+?
13. Vi sao crash `KERNEL_MODE_HEAP_CORRUPTION` la signal ve invariant allocator, khong chi "write sai"?
14. Vi sao anti-cheat/EDR co the muon dat rule tables trong Secure Pool?

## 6. Quarkslab IUM / VSM / VTL Debugging

Source:

- https://blog.quarkslab.com/debugging-windows-isolated-user-mode-ium-processes.html

### Explain

IUM Trustlets chay trong VTL1. Normal kernel/user world la VTL0. VTL1 co Secure Kernel va isolated user-mode processes, vi du `LSAIso.exe` khi Credential Guard bat. Diem quan trong: ring 0 VTL0 khong doc duoc VTL1. "Kernel mode" khong con dong nghia voi "toan quyen tren may".

Quarkslab dung nested virtualization de debug Hyper-V/hypervisor context, roi tu hypercall `HvCallVtlReturn` suy ra Secure Kernel state. Bai nay ket hop:

- Hyper-V/VTL mental model,
- VMCS state,
- CR3/RSP/RIP reasoning,
- virtual-to-physical page walk,
- Secure Kernel module base discovery.

### Why It Works

Neu khong attach duoc debugger vao Trustlet tu VTL0, minh phai debug lop ben duoi no: hypervisor. Hypervisor thay duoc VTL transition va VMCS. Tu VMCS lay duoc guest context. Tu CR3 co the page-walk dia chi VTL1. Tu return address co the tim Secure Kernel image.

### Research Lesson

Day la bai hoc ve privilege model hien dai:

```text
ring 3/0 is not enough
  -> VTL0/VTL1 matters
  -> hypervisor controls translation/protection
  -> Secure Kernel owns selected secrets
```

### Why Questions

1. Vi sao VTL la truc trust rieng, orthogonal voi ring 0/ring 3?
2. Vi sao kernel debugger VTL0 khong du de debug Trustlet?
3. Vi sao virtual TPM va Credential Guard lien quan IUM?
4. Vi sao hypercall/VTL return la diem quan sat tot?
5. Vi sao VMCS chua CR3/RSP/RIP co gia tri cho reverse engineering?
6. Vi sao can page walk thay vi doc virtual address truc tiep?
7. Vi sao return address tren stack co the giup tim Secure Kernel base?
8. Vi sao offsets Hyper-V/Secure Kernel phai coi la build-specific?
9. Vi sao nested virtualization huu ich cho lab?
10. Vi sao "kernel R/W primitive" trong VTL0 khong tu dong bypass Credential Guard?
11. Vi sao VBS/HVCI notes phai noi ro target nam VTL nao?
12. Vi sao research vao IUM can ghi ro ethical/lab boundary?

## 7. Core-jmp: How To Read The Site

Source:

- https://core-jmp.org/

Core-jmp co nhieu bai dang rewrite/tong hop tu primary source khac. Gia tri lon nhat la source map nhanh: no dua link den blog goc, GitHub, Microsoft, LOLBAS, MITRE, Huntress, NVISO, Synacktiv, Incendium, GhostWolfLab, etc. Khi doc, dung thu tu:

```text
core-jmp summary
  -> upstream primary source
  -> official docs if API/Windows behavior involved
  -> local repo note
  -> own lab-safe summary
```

### Windows Posts Worth Detailed Follow-Up

| Topic | Why it matters | Read next |
|---|---|---|
| Hooking/named pipes | IPC boundary, message protocol, impersonation. | Synacktiv `thats_no_pipe`, Microsoft pipe docs, pipe-intercept. |
| Automating MS-RPC research | RPC endpoint enumeration, dynamic clients, fuzzing, ETW/ProcMon triage. | Incendium posts, NtObjectManager, RpcView, RPCMon, MS-RPC-Fuzzer. |
| Windows Search URI NTLM coercion | URI handler -> shell/Explorer boundary -> outbound auth coercion. | Huntress source, Geoff Chappell ExplorerFrame notes, protocol handler docs. |
| Win32k type confusion | GUI kernel object lifetime, async paths, patch-diff proof. | s4dbrd primary writeup, MSRC CVE page, local Win32k docs. |
| PDB dynamic offsets | Build drift, symbol-guided offsets, no hardcoded structure assumption. | Local runtime PDB notes. |
| Process callback enumeration | Callback arrays as visibility surface. | Local callback-surfaces and detection docs. |
| Kernel Karnage callback patching | Good for understanding why callback loss matters; too operational to copy. | NVISO source as defensive reading. |
| Vanguard guarded regions | Page-table isolation, CR3 switching, scheduler/context hooks. | Local page-table/HVCI/anti-cheat notes. |
| Early boot mitigation config | How policy becomes kernel global state. | ERNW CmControlVector data/scripts. |
| Segment heap/paging primers | Teaching material for allocator and VA/PA reasoning. | Kernullist/Melatoni then local docs. |

### Why Questions For Core-jmp Intake

1. Bai nay la primary research hay rewrite?
2. Co link goc khong? Neu co, link goc noi gi khac?
3. Claim nao co vendor/MSRC/Microsoft docs confirm?
4. Claim nao chi la PoC/GitHub/forum?
5. Topic nay da co trong repo chua?
6. Neu da co, no them angle moi nao: build, telemetry, source, primitive, failure mode?
7. Co operational payload/recipe khong? Neu co, cat bo phan do.
8. Primitive la gi: info leak, type confusion, UAF, registry hijack, policy bypass, callback tamper, IOCTL semantic action?
9. Preconditions la gi: admin, medium-integrity admin, signed driver, vulnerable build, network path, specific policy?
10. Defender thay gi: registry, process, ETW, crash, driver load, outbound auth, pipe connection, RPC call?
11. Modern mitigation nao lam thay doi exploitability?
12. Cai gi can lab verify truoc khi coi la fact?

## 8. MS-RPC Research: Automate But Keep Evidence

Sources:

- https://core-jmp.org/2026/05/automating-ms-rpc-vulnerability-research/
- https://core-jmp.org/2026/05/recursively-fuzzing-ms-rpc-structures-and-monitoring-using-etw/
- https://www.incendium.rocks/posts/Automating-MS-RPC-Vulnerability-Research/
- https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools/tree/main/NtObjectManager
- https://github.com/silverf0x/RpcView
- https://github.com/cyberark/RPCMon
- https://github.com/warpnet/MS-RPC-Fuzzer

### Explain

MS-RPC research kho vi interface co IDL/NDR encoding, pointers, unions, context handles va endpoint security. Automation giup:

- enumerate interfaces/endpoints,
- generate dynamic clients,
- fuzz nested structures,
- watch ETW/syscall/process/file/registry side effects,
- replay crash,
- map high-privilege action back to procedure.

### Why It Matters

Nhieu Windows services expose RPC. Bug khong nhat thiet la memory corruption; co the la confused deputy, coercion, file write, load DLL, printer/spooler-style semantic action.

### Why Questions

1. Vi sao RPC fuzzing can IDL/NDR knowledge thay vi raw byte mutation?
2. Vi sao union/embedded pointer lam fuzzer de generate invalid input?
3. Vi sao ETW can di kem crash monitoring?
4. Vi sao high-privilege side effect co the quan trong hon crash?
5. Vi sao context handle lifetime la bug source?
6. Vi sao endpoint ACL va authentication level la precondition?
7. Vi sao replay crash can luu exact serialized input?
8. Vi sao ProcMon/ETW/canary files giup tim semantic bugs?
9. Vi sao RPC interface map nen link den service identity?
10. Vi sao coercion bug khong can memory corruption van co impact?

## 9. Anti-Cheat vs EDR Bypass: Shared Mechanics, Different Ethics

Source:

- https://whiteknightlabs.com/2024/02/09/a-technical-deep-dive-comparing-anti-cheat-bypass-and-edr-bypass/

### Explain

Anti-cheat va EDR cung nhin vao process, memory, handle, module, thread, kernel driver, hook va telemetry. Khac nhau:

- Anti-cheat bao ve game integrity/fair play.
- EDR bao ve enterprise host, identity, secrets va forensic visibility.

Neu chi nhin technique, hai ben co overlap: injection, hook, memory scan, kernel driver, callbacks, timing, anti-debug. Nhung threat model va legal context khac nhau. Mot "bypass" trong game co the la ToS violation; EDR bypass gan voi compromise va malware.

### Defensive Takeaway

Hoc tu anti-cheat o muc:

- cross-view process/module/memory checks,
- handle access monitoring,
- kernel/user telemetry fusion,
- tamper-evident state,
- latency-sensitive detection design.

Khong hoc de viet cheat hoac EDR evasion.

### Why Questions

1. Vi sao anti-cheat va EDR deu quan tam process injection?
2. Vi sao anti-cheat co the chap nhan invasive telemetry hon enterprise EDR?
3. Vi sao kernel driver tang visibility nhung tang crash/security risk?
4. Vi sao hooking vua la detection method vua la tamper target?
5. Vi sao handle access la signal quan trong cho ca game va EDR?
6. Vi sao anti-cheat trust model khac voi endpoint security trust model?
7. Vi sao attacker co the reuse concept giua hai ecosystem?
8. Vi sao defender phai phan biet research, cheat, malware va red-team simulation?

## 10. Operational Evasion Sources: Keep Only Detection Models

Sources:

- https://github.com/depthsecurity/PositiveIntent
- https://github.com/kasturixbm5/staged-DLL-Injection-SMB-
- https://codeby.net/threads/obkhod-windows-defender-i-amsi-prakticheskii-gaid-po-defense-evasion-dlya-red-team.92763/
- https://core-jmp.org/2026/06/bypassing-windows-defender-amsi-defense-evasion-red-team-guide/
- https://core-jmp.org/2026/05/patchless-amsi-bypass-via-page-guard-exceptions/
- https://core-jmp.org/2026/05/process-injection-without-the-usual-red-flags-abusing-windows-primitives-to-outsmart-classic-edr-telemetry/

### What To Extract

Chi lay cac signal phong thu:

- .NET assembly load bat thuong.
- Resource-heavy loader va entropy shaping.
- AMSI/ETW telemetry gap hoac inconsistent provider behavior.
- Remote thread / cross-process memory / module load ancestry.
- DLL path tu network share hoac user-writable path.
- AppLocker/LOLBAS pressure map.
- Parent/child/process-integrity mismatch.

### What Not To Extract

Khong lay:

- command lines,
- payload generation,
- bypass implementation detail,
- patch bytes,
- direct syscall stubs,
- hardware-breakpoint bypass recipe,
- C2 staging instructions.

### Why Questions

1. Vi sao AMSI, ETW, Defender static scan va AppLocker la cac layer rieng?
2. Vi sao bypass mot layer khong co nghia la bypass tat ca?
3. Vi sao telemetry gap la signal, khong chi la absence of evidence?
4. Vi sao .NET loader co nhieu detection surface: CLR load, assembly metadata, resources, entropy, strings?
5. Vi sao remote module load tu SMB share dang nghi trong workstation binh thuong?
6. Vi sao process injection detection khong nen chi tim `WriteProcessMemory`?
7. Vi sao memory permission transition va thread start address quan trong?
8. Vi sao AppLocker/LOLBAS abuse la policy design issue, khong chi malware issue?
9. Vi sao EDR tamper notes phai co cross-view checks?
10. Vi sao khong nen import offensive code vao knowledge base defensive?

## 11. Suggested Detailed Docs To Write Next

Neu tach thanh deep-dive rieng, thu tu uu tien:

1. `docs/userland-to-kernel/named-pipe-interception-and-ipc-trust.md`
2. `docs/kernel-research/windows-patch-diff-llm-workflow.md`
3. `docs/windows-heap/kernel-segment-heap-modern-pool-notes.md`
4. `docs/kernel-research/ms-rpc-fuzzing-and-etw-triage.md`
5. `docs/mitigations/vsm-ium-debugging-source-map.md`
6. `docs/detection-and-mitigation/operational-evasion-source-safety-map.md`

Moi file nen co:

```text
summary
  -> mental model
  -> why it works
  -> what breaks it
  -> safe lab validation
  -> defender telemetry
  -> 20+ why questions
```

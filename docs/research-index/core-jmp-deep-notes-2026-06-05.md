# Core-jmp Deep Notes 2026-06-05

Backlinks: [source reading notes](source-reading-notes-2026-06-05.md) | [source deep notes](source-deep-notes-2026-06-05.md) | [topic index](topic-index.md)

## Scope

Ghi chú này tập trung vào các bài core-jmp có ích cho Windows reverse engineering, kernel exploitation research, BYOVD, IPC, RPC, EDR telemetry và mitigation reasoning. Core-jmp thường là bài rewrite/source-map, nên cách đọc đúng là:

```text
core-jmp post -> upstream source -> primitive -> invariant -> precondition -> telemetry -> safe lab question
```

Không nhập lại PoC, command chain, payload, bypass recipe, patch byte, shellcode, C2, credential dumping hoặc trigger exploit. Nếu bài có phần quá operational, chỉ giữ detection model và câu hỏi nghiên cứu.

Nguồn site chính:

- https://core-jmp.org/
- https://core-jmp.org/page/2/
- https://core-jmp.org/page/3/
- https://core-jmp.org/page/4/
- https://core-jmp.org/page/5/
- https://core-jmp.org/page/6/
- https://core-jmp.org/page/7/
- https://core-jmp.org/page/8/
- https://core-jmp.org/page/9/

## Reading Map

| Nhóm | Bài nên đọc kỹ | Giá trị học chính | Cách đưa vào repo |
|---|---|---|---|
| IPC | Hooking Windows Named Pipes | NPFS, ACL, impersonation, pipe traffic visibility | Bổ sung IPC boundary atlas |
| UAC | Eventvwr UAC bypass via `mscfile` | HKCU/HKLM class lookup, auto-elevation, integrity transition | Đọc như detection case |
| Kernel callback | Kernel Karnage, Enumerating Process Creation Callbacks | EDR telemetry phụ thuộc kernel callback, build drift, symbol recovery | Đọc như tamper-risk model |
| BYOVD | `gdrv3.sys`, BYOVD certificate abuse | Signed driver trust, IOCTL primitive, blocklist/certificate pressure | Gắn vào BYOVD threat model |
| Dynamic offsets | No More Hardcoded Kernel Offsets | PDB-based runtime resolution, version drift | Gắn vào patch-diff workflow |
| RPC | Automating MS-RPC, Recursively fuzzing MS-RPC | Interface discovery, opnum, IDL, canary, ETW | Gắn vào fuzzing workflow |
| Memory | Virtual memory fundamentals, kernel segment heap via external source | Page table, COW, allocator metadata, pool evolution | Gắn vào memory model docs |
| VBS/anti-cheat | Vanguard guarded regions, IUM external source | CR3/PML4, VTL boundary, trust isolation | Gắn vào HVCI/VBS docs |
| Evasion posts | AMSI/Defender, process injection, PPL, LSASS, Shadow SSDT | Detection model only | Không nhập recipe |
| Network/NTLM | Search URI NTLM coercion, Snipping Tool deep link | Protocol handler coercion, outbound auth telemetry | Gắn vào Windows URL handler/NTLM note |

## 1. Hooking Windows Named Pipes

Sources:

- https://core-jmp.org/2026/04/hooking-windows-named-pipes/
- https://github.com/gabriel-sztejnworcel/pipe-intercept
- https://www.synacktiv.com/en/publications/hooking-windows-named-pipes
- https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipes
- https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
- https://learn.microsoft.com/en-us/windows/win32/ipc/impersonating-a-named-pipe-client

Ý chính: named pipe là IPC có tên, chạy qua NPFS, được rất nhiều service dùng để nói chuyện với client local hoặc remote. Bài này hay vì nó ép mình nhìn IPC như một protocol boundary thật sự, không chỉ là "handle đọc/ghi".

Cơ chế cần hiểu:

- Pipe server tạo endpoint có tên và security descriptor.
- Client mở endpoint qua tên pipe và nhận handle nếu DACL cho phép.
- Server có thể impersonate client, nên danh tính của client là một phần của logic bảo mật.
- Pipe có nhiều I/O model: blocking, overlapped, message mode, byte mode.
- Nếu một tool đứng giữa client/server, thứ quan trọng không chỉ là byte stream mà còn là timing, instance ordering, impersonation context và lỗi I/O.

Vì sao đây là attack surface: nhiều service tự tin rằng client local là đáng tin, hoặc kiểm tra identity quá muộn. Nếu protocol bên trong pipe không authenticate từng message, attacker có thể học grammar của service, replay message, fuzz field hoặc lợi dụng nhầm lẫn server/client.

Đọc như defender:

- Liệt kê pipe name, owner process, DACL, instance count.
- Hỏi pipe nào cho `Everyone`/`Authenticated Users` quyền quá rộng.
- Hỏi server có gọi impersonation không, và gọi trước hay sau khi parse message.
- Hỏi message có length prefix, version, checksum, auth tag hoặc session binding không.
- Hỏi telemetry nào thấy được: object access, process handle, ETW provider, service logs.

Câu hỏi "vì sao":

1. Vì sao Windows cần named pipe thay vì chỉ dùng TCP localhost?
2. Vì sao pipe name là boundary yếu nếu DACL rộng?
3. Vì sao server phải impersonate trước khi làm hành động thay mặt client?
4. Vì sao parse message trước khi kiểm tra identity là nguy hiểm?
5. Vì sao overlapped I/O làm interception khó hơn blocking I/O?
6. Vì sao message mode giúp protocol dễ audit hơn byte mode?
7. Vì sao một pipe có nhiều instance có thể tạo race trong test?
8. Vì sao client/server đều có thể nhầm lẫn vai trò khi tool proxy đứng giữa?
9. Vì sao traffic nhìn "binary" vẫn phải được mô hình hóa như protocol?
10. Vì sao pipe ACL phải nằm trong threat model của service, không phải chi tiết phụ?
11. Vì sao detection không nên chỉ alert theo pipe name lạ?
12. Vì sao cần gắn pipe event với process ancestry và token identity?

## 2. Eventvwr UAC Bypass via `mscfile`

Sources:

- https://core-jmp.org/2026/05/eventvwr-uac-bypass-mscfile-hkcu-hijack/
- https://attack.mitre.org/techniques/T1548/002/
- https://lolbas-project.github.io/lolbas/Binaries/Eventvwr/
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/

Ý chính: bài này không nên đọc để học "chạy bypass", mà nên đọc để hiểu một mẫu trust-asymmetry: binary auto-elevated chạy ở High integrity, nhưng trong quá trình mở file/console lại tra cứu handler từ vùng người dùng có thể shadow per-machine setting.

Cơ chế cần hiểu:

- UAC tách token admin thành medium/high integrity token.
- Một số binary Microsoft-signed có manifest auto-elevate.
- Windows class association có lớp per-user và per-machine; HKCR là merged view.
- Nếu auto-elevated process gọi shell để mở một file type/progid, handler được resolve theo chain đó.
- Child process có thể kế thừa integrity context của parent nếu shell launch không ràng buộc chặt.

Vì sao Microsoft thường không xử lý như security boundary: UAC là usability boundary, không phải boundary để chống attacker đã có code execution trong admin account. Điều này không làm kỹ thuật "an toàn"; nó chỉ nghĩa là enterprise phải tự thiết kế least privilege và detection.

Đọc như defender:

- Registry write vào per-user class handler của sensitive progid.
- Auto-elevated binary có parent bất thường.
- Child/grandchild không phải process hợp lệ của tool gốc.
- Integrity transition Medium -> High không đi qua consent path bình thường.
- Clean-up quá nhanh vẫn để lại dấu trong registry/event telemetry nếu audit bật.

Câu hỏi "vì sao":

1. Vì sao HKCU được ưu tiên trước HKLM trong class lookup?
2. Vì sao thiết kế đó tiện cho user customization nhưng nguy hiểm với auto-elevate?
3. Vì sao UAC không được coi là security boundary?
4. Vì sao admin local với UAC default gần như admin-equivalent nếu chạy code lạ?
5. Vì sao allowlisting payload hiệu quả hơn chỉ chặn eventvwr?
6. Vì sao detection nên nhìn process tree chứ không chỉ binary name?
7. Vì sao registry key tồn tại ngắn vẫn có giá trị forensic?
8. Vì sao "by design" vẫn là risk trong enterprise?
9. Vì sao parent process của auto-elevated binary là tín hiệu mạnh?
10. Vì sao cần hunt cả sibling pattern như handler/progid khác?
11. Vì sao AV signature khó bắt API call hợp lệ?
12. Vì sao policy tốt nhất là giảm local admin membership?

## 3. Kernel Karnage: Callback Tamper Risk

Sources:

- https://core-jmp.org/2026/06/kernel-karnage-part-1-patching-windows-kernel-callbacks-edr-bypass/
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutine
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetloadimagenotifyroutine
- https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/patchguard

Ý chính: EDR dựa nhiều vào callback kernel như process creation, thread creation, image load, registry callback. Bài này đáng học vì nó cho thấy telemetry "được support" vẫn có điểm yếu nếu attacker có write primitive trong kernel.

Cơ chế cần hiểu:

- Kernel callback là API hợp pháp để driver đăng ký nhận event.
- OS giữ callback list/array trong kernel memory.
- PatchGuard bảo vệ một số cấu trúc trọng yếu, nhưng không phải mọi telemetry list đều được bảo vệ như nhau.
- Build drift làm offset/signature thay đổi; hardcode dễ crash.
- Một byte sai trong pattern matching kernel có thể thành BSOD, nên kernel research phải luôn có WinDbg, symbol và rollback VM.

Đọc như defender:

- Kernel callback là signal source, không phải root of trust tuyệt đối.
- Driver inventory, CI policy, blocklist, HVCI và VBS quan trọng hơn một rule EDR đơn lẻ.
- Nếu callback mất đột ngột, đó là tamper signal.
- Nếu callback vẫn còn nhưng event pipeline im lặng, phải kiểm tra filter driver, ETW, user-mode sensor và cloud reachability.

Câu hỏi "vì sao":

1. Vì sao EDR thích kernel callback hơn user-mode hook?
2. Vì sao callback hợp pháp lại thành điểm tập trung của tamper?
3. Vì sao PatchGuard không thể bảo vệ mọi list mà không phá compatibility?
4. Vì sao hardcoded offset là nợ kỹ thuật trong kernel tooling?
5. Vì sao crash trong lab là dữ liệu, nhưng crash trên endpoint là incident?
6. Vì sao callback loss nên được xem là health signal?
7. Vì sao driver load telemetry phải đi trước callback telemetry?
8. Vì sao BYOVD biến callback tamper thành realistic risk?
9. Vì sao symbol-based recovery tốt hơn pattern byte thuần?
10. Vì sao cần cross-check nhiều sensor thay vì tin một callback family?
11. Vì sao process creation callback không đủ để bắt injection đã xảy ra?
12. Vì sao kernel tamper phải được threat-model dưới HVCI/WDAC?

## 4. Enumerating Windows Process Creation Callbacks

Sources:

- https://core-jmp.org/2026/05/enumerating-windows-process-creation-callbacks/
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex

Ý chính: enumeration callback giúp biết driver nào đang đăng ký nhận process creation event. Đây là kỹ năng blue-team/research tốt nếu làm ở lab có symbol và quyền hợp lệ; nó cũng là lý do phải tránh public recipe operational.

Cơ chế cần hiểu:

- Public API cho đăng ký callback không nhất thiết expose API liệt kê toàn bộ callback.
- Researcher thường phải dựa vào symbol, reverse engineering hoặc memory introspection.
- Entry không nhất thiết là raw function pointer; có thể có wrapper/block/refcount bit.
- Mapping callback pointer về module owner giúp biết EDR/AV/driver nào đang giám sát.

Đọc như defender:

- Lập baseline callback owner theo build/EDR version.
- Alert khi callback owner biến mất, trùng lặp lạ hoặc trỏ ra module không mong đợi.
- Kết hợp với driver load/unload, Code Integrity, registry service key và crash dump.

Câu hỏi "vì sao":

1. Vì sao Windows không cung cấp API đơn giản để user liệt kê kernel callbacks?
2. Vì sao callback entry thường cần decode/mask trước khi map về routine?
3. Vì sao module owner quan trọng hơn địa chỉ pointer đơn lẻ?
4. Vì sao baseline phải theo Windows build và EDR version?
5. Vì sao callback list sạch không chứng minh endpoint sạch?
6. Vì sao một malicious driver có thể unregister thay vì patch?
7. Vì sao PatchGuard behavior phải được kiểm chứng trên build cụ thể?
8. Vì sao symbol server là dependency bảo mật trong lab?
9. Vì sao callback enumeration nên là health check, không phải detection duy nhất?
10. Vì sao crash dump tốt hơn screenshot trong kernel triage?

## 5. `gdrv3.sys` and Signed Driver Primitives

Sources:

- https://core-jmp.org/2026/05/gdrv3-sys-reverse-engineering-a-signed-kernel-driver-with-13-hardware-access-primitives/
- https://www.loldrivers.io/
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/

Ý chính: signed driver không tự động an toàn. Nếu driver expose IOCTL cho physical memory, MSR, port I/O hoặc kernel copy mà không kiểm soát caller, chữ ký số chỉ chứng minh nguồn ký, không chứng minh primitive an toàn.

Cơ chế cần hiểu:

- BYOVD thường bắt đầu từ driver hợp lệ, đã ký.
- IOCTL surface là API thật của driver; mỗi IOCTL là một mini protocol.
- Dangerous primitive thường nằm ở class: arbitrary read/write, physical mapping, MSR write, port I/O, model-specific hardware access.
- Vulnerability nằm ở permission model và input validation, không chỉ ở bug memory corruption.

Đọc như defender:

- Inventory driver hash, signer, service install path.
- So với LOLDrivers/blocklist/vendor advisory.
- Audit Device Object ACL và IOCTL access check.
- Không chỉ chặn hash; cần policy cho signer, path, CI và vulnerable driver blocklist.

Câu hỏi "vì sao":

1. Vì sao driver signed vẫn có thể nguy hiểm?
2. Vì sao IOCTL giống RPC endpoint trong kernel?
3. Vì sao physical memory primitive mạnh hơn virtual read/write thường?
4. Vì sao MSR write primitive thường liên quan mitigation bypass risk?
5. Vì sao Device Object ACL có giá trị như firewall rule?
6. Vì sao hash blocklist luôn đi sau attacker?
7. Vì sao signer policy cần đi cùng version policy?
8. Vì sao driver utility phần cứng hay có primitive rộng?
9. Vì sao kernel pointer leak làm BYOVD chain dễ hơn?
10. Vì sao cần test trên HVCI-on và HVCI-off?
11. Vì sao vendor removal khó hơn OS block?
12. Vì sao driver telemetry phải giữ cả load và failed-load events?

## 6. BYOVD Certificate Abuse

Sources:

- https://core-jmp.org/2026/05/byovd-attack-surface-vulnerability-to-certificate-abuse/
- https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules

Ý chính: BYOVD đang chuyển từ "tìm driver cũ có CVE" sang "lạm dụng trust chain/certificate/signed ecosystem". Điều này làm phòng thủ bằng blocklist hash đơn lẻ yếu đi.

Cơ chế cần hiểu:

- Windows driver trust dựa vào signing policy, signer, certificate chain, timestamp và policy hiện hành.
- Cross-signed/legacy trust có lịch sử dài, nhiều ngoại lệ compatibility.
- Một driver có thể không có CVE public nhưng vẫn expose primitive nguy hiểm.
- Attacker thích signed driver vì nó đi qua nhiều cổng kiểm tra mặc định.

Đọc như defender:

- WDAC/HVCI không chỉ là mitigation; chúng là policy engine để giảm driver trust surface.
- Blocklist phải được cập nhật và enforced.
- Certificate revocation không phải lúc nào cũng đủ vì timestamp/compatibility.
- Driver allowlist theo business need đáng tin hơn "cho tất cả signed".

Câu hỏi "vì sao":

1. Vì sao chữ ký số là identity, không phải proof of safety?
2. Vì sao compatibility làm Microsoft khó revoke rộng?
3. Vì sao timestamp làm revocation phức tạp?
4. Vì sao driver blocklist cần update qua OS/security intelligence?
5. Vì sao allowlist theo business role mạnh hơn denylist?
6. Vì sao certificate abuse khó hunt hơn CVE hash?
7. Vì sao vulnerable driver không nhất thiết có exploit public?
8. Vì sao HVCI có thể giảm một số primitive nhưng không xóa hết risk?
9. Vì sao attacker thích driver vendor nhỏ/legacy?
10. Vì sao incident response phải lưu driver file và signer metadata?

## 7. No More Hardcoded Kernel Offsets

Sources:

- https://core-jmp.org/2026/05/no-more-hardcoded-kernel-offsets-a-practical-guide-to-dynamic-offset-resolution-for-edr/
- https://github.com/joshterrill/post-patch-postmortem
- https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/microsoft-public-symbols

Ý chính: hardcoded kernel offsets làm research nhanh ở một build nhưng vỡ ngay khi update. Dynamic symbol/PDB workflow biến "offset" thành dữ liệu được resolve theo build.

Cơ chế cần hiểu:

- Kernel structure layout thay đổi theo build, feature flag, compiler, mitigation.
- Public symbols không luôn có mọi field private, nhưng vẫn giúp định vị function/type/relative pattern.
- Offset không nên là claim độc lập; nó phải đi kèm build number, PDB GUID/age, binary hash.
- LLM có thể giúp đọc diff, nhưng không thay thế evidence từ BinDiff, symbols, disassembly và VM.

Đọc như researcher:

- Ghi mọi offset cùng build, module timestamp, PDB identity.
- Dùng patch diff để tìm changed function, sau đó verify bằng dynamic analysis.
- Tách "hypothesis generated by LLM" khỏi "confirmed in debugger".

Câu hỏi "vì sao":

1. Vì sao offset đúng hôm nay có thể sai sau Patch Tuesday?
2. Vì sao PDB GUID/age quan trọng hơn tên file?
3. Vì sao hash binary cần nằm trong note?
4. Vì sao function diff tốt hơn chỉ diff string?
5. Vì sao LLM dễ bịa field name nếu không có symbol evidence?
6. Vì sao build-specific VM là bắt buộc để validate?
7. Vì sao crash triage nên ghi register/context trước khi sửa code?
8. Vì sao offset-free design vẫn cần fallback khi symbol thiếu?
9. Vì sao dynamic resolution cũng là attack surface nếu parser sai?
10. Vì sao defender cũng cần version-aware detection?

## 8. Automating MS-RPC Vulnerability Research

Sources:

- https://core-jmp.org/2026/05/automating-ms-rpc-vulnerability-research/
- https://core-jmp.org/2026/05/recursively-fuzzing-ms-rpc-structures-and-monitoring-using-etw/
- https://github.com/mandiant/MS-RPC-Fuzzer
- https://github.com/tyranid/WindowsRpcClients
- https://github.com/silverf0x/RpcView

Ý chính: MS-RPC research mạnh khi tự động hóa đúng: discover interface, parse IDL, generate client, fuzz opnum/structure, monitor ETW/canary/crash, replay. Nhưng tự động hóa không thay thế hiểu semantics.

Cơ chế cần hiểu:

- RPC interface có UUID, version, binding, authn/authz và opnum.
- IDL mô tả kiểu dữ liệu; nested struct/union/pointer là nơi fuzzing dễ thiếu coverage.
- Crash không tự động là vuln; phải phân biệt client-side marshalling bug, server exception, access denied và real memory corruption.
- Coercion-style bug không nhất thiết crash; nó tạo outbound auth hoặc side effect.

Đọc như researcher:

- Ghi interface inventory trước khi fuzz.
- Log auth context, endpoint, opnum, input shape, server process, ETW event, canary result.
- Ưu tiên replay minimal test case hơn số lượng crash.
- Tách fuzzing local lab khỏi bất kỳ target third-party nào.

Câu hỏi "vì sao":

1. Vì sao RPC interface giống attack surface hơn là implementation detail?
2. Vì sao UUID/version phải đi cùng endpoint binding?
3. Vì sao authn level thay đổi kết quả fuzz?
4. Vì sao opnum không có symbol name vẫn cần semantic labeling?
5. Vì sao nested union/pointer khó fuzz hơn scalar?
6. Vì sao ETW giúp thấy side effect không crash?
7. Vì sao canary tốt hơn chỉ nhìn process exit?
8. Vì sao crash replay quan trọng hơn crash count?
9. Vì sao coercion bug cần outbound network telemetry?
10. Vì sao fuzzing cần reset service state giữa case?
11. Vì sao IDL generated client có thể sai nếu type recovery sai?
12. Vì sao automation phải tạo evidence bundle, không chỉ log text?

## 9. Windows Search URI / NTLM Coercion

Sources:

- https://core-jmp.org/2026/06/one-click-one-hash-unpatched-ntlm-coercion-in-windows-search-uri-handler/
- https://core-jmp.org/2026/05/cve-2026-33829-how-a-deep-link-in-windows-can-expose-net-ntlm-credentials/
- https://attack.mitre.org/techniques/T1187/

Ý chính: protocol/deep-link handler có thể biến một click thành outbound authentication. Đây là vấn đề boundary giữa shell UX, URL handler, file preview/icon parsing và NTLM.

Cơ chế cần hiểu:

- Windows shell đăng ký nhiều protocol handler để tiện mở app/system feature.
- Handler có thể resolve path/UNC/resource trước khi user hiểu chuyện gì xảy ra.
- Nếu resolution chạm SMB/WebDAV, Windows có thể thử NTLM authentication.
- Leak hash không phải code execution, nhưng có thể thành relay/cracking risk tùy network posture.

Đọc như defender:

- Monitor suspicious protocol handler invocation from browser/mail/chat.
- Monitor outbound SMB/WebDAV to Internet.
- Harden NTLM, SMB signing, egress filtering, WebClient exposure.
- Treat deep-link coercion as identity boundary issue, not only endpoint issue.

Câu hỏi "vì sao":

1. Vì sao một URL handler lại có thể gây network authentication?
2. Vì sao shell convenience thường tạo hidden trust path?
3. Vì sao Net-NTLM leak vẫn nguy hiểm dù không lộ plaintext password?
4. Vì sao outbound SMB to Internet phải bị chặn ở network layer?
5. Vì sao browser/mail process ancestry quan trọng?
6. Vì sao patched handler này không đảm bảo sibling handler an toàn?
7. Vì sao icon/preview parsing có thể gây side effect?
8. Vì sao NTLM relay phụ thuộc SMB signing/channel binding?
9. Vì sao detection cần URL/protocol và network event cùng lúc?
10. Vì sao user training không đủ nếu click chỉ cần một lần?

## 10. Virtual Memory Fundamentals

Sources:

- https://core-jmp.org/2026/05/fundamentals-of-virtual-memory/
- https://learn.microsoft.com/en-us/windows/win32/memory/virtual-memory

Ý chính: đây là bài nền nên đọc trước khi đọc kernel heap, BYOVD R/W, CR3/PML4, KASLR, process injection hoặc VBS. Nếu không nắm virtual memory, mọi primitive kernel sẽ bị hiểu thành "địa chỉ là số" quá đơn giản.

Cơ chế cần hiểu:

- Virtual address phải qua page table để thành physical address.
- Process có address space riêng, kernel có vùng shared/privileged tùy mode và mitigation.
- Page table entry chứa permission/state: present, writable, executable, user/supervisor, copy-on-write.
- Demand paging và COW nghĩa là mapping logic không đồng nghĩa page vật lý đã tồn tại cố định.

Đọc như exploit researcher:

- Primitive read/write phải nói rõ đọc virtual hay physical.
- KASLR bypass là bài toán tìm base/translation, không phải "đoán địa chỉ".
- SMEP/SMAP/NX/PXN là permission boundary của CPU/page table.
- CR3 switch, PML4 clone, HLAT, EPT đều là biến thể của translation control.

Câu hỏi "vì sao":

1. Vì sao virtual address không đủ để nói "đọc kernel memory"?
2. Vì sao same virtual address ở hai process có thể trỏ physical khác?
3. Vì sao COW làm forensic memory khó hơn nhìn mapping?
4. Vì sao page permissions là mitigation chứ không chỉ metadata?
5. Vì sao PTE bit nhỏ có thể quyết định exploitability?
6. Vì sao physical memory R/W primitive vượt qua một số abstraction?
7. Vì sao KASLR là address discovery problem?
8. Vì sao page fault là signal tốt trong dynamic analysis?
9. Vì sao VBS/HVCI thêm translation boundary mới?
10. Vì sao memory note phải ghi CR3/process context?

## 11. Vanguard Guarded Regions / Anti-Cheat Kernel Design

Sources:

- https://core-jmp.org/2026/06/reverse-engineering-valorant-vanguard-guarded-regions-pml4-cr3-swap-context-hook/
- https://reversing.info/
- https://whiteknightlabs.com/2024/02/09/a-technical-deep-dive-comparing-anti-cheat-bypass-and-edr-bypass/

Ý chính: anti-cheat và EDR khác mục tiêu, nhưng cùng đụng vào kernel observation, handle policy, memory scanning, page table tricks và trust boundaries. Đọc bài anti-cheat để học OS internals, không để học cheat bypass.

Cơ chế cần hiểu:

- Game anti-cheat có thể bảo vệ vùng memory bằng page table/CR3/PML4 manipulation.
- Whitelisted thread/context quyết định lúc nào mapping được nhìn thấy.
- SwapContext/hook/scheduler context là điểm liên kết giữa CPU scheduling và memory visibility.
- Đây là cùng họ kiến thức với VBS/HVCI: ai kiểm soát translation thì kiểm soát visibility.

Đọc như researcher:

- Tách "memory hiding" khỏi "memory protection".
- Hỏi boundary nằm ở CPU mode, page table, hypervisor hay policy.
- So sánh anti-cheat với EDR: anti-cheat bảo vệ game integrity, EDR bảo vệ endpoint/security telemetry.

Câu hỏi "vì sao":

1. Vì sao page table trick có thể giấu memory khỏi reader không đúng context?
2. Vì sao CR3/PML4 là điểm quyền lực trong memory visibility?
3. Vì sao scheduler context liên quan đến security boundary?
4. Vì sao anti-cheat có incentive can thiệp sâu hơn app thường?
5. Vì sao EDR không thể copy nguyên anti-cheat model?
6. Vì sao kernel driver không tự động thắng nếu hypervisor kiểm soát translation?
7. Vì sao thread whitelist là both policy và attack surface?
8. Vì sao detection của DMA cheat phải nhìn IOMMU/PCIe/topology?
9. Vì sao "ẩn memory" thường tạo side effect ở TLB/performance/crash?
10. Vì sao cần phân biệt bypass và measurement?

## 12. PPL Abuse and Protected Process Reasoning

Sources:

- https://core-jmp.org/2026/05/ppl-abuse-ghost-wolf-lab-rewrite/
- https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-

Ý chính: PPL là trust hierarchy cho process nhạy cảm. Bài này nên đọc để hiểu vì sao attacker nhắm vào trust anchor, signer level, service relationship và race/proxy path, không chỉ nhắm vào process memory.

Cơ chế cần hiểu:

- PPL hạn chế process thấp hơn mở handle mạnh vào process được bảo vệ.
- Protection level phụ thuộc signer/trust category.
- Nếu một trusted process/proxy thực hiện hành động thay attacker, boundary bị bẻ theo kiểu confused deputy.
- BYOVD có thể cố thay đổi kernel state liên quan protection, nhưng HVCI/KDP/CI làm chuyện này khó và build-specific.

Đọc như defender:

- Bảo vệ EDR service không chỉ là set PPL.
- Cần monitor service control, trusted binary abuse, driver load, handle request failure/success.
- PPL bypass claim phải luôn kiểm chứng build, signer, HVCI, WDAC state.

Câu hỏi "vì sao":

1. Vì sao PPL tồn tại nếu admin vẫn có nhiều quyền?
2. Vì sao signer level quan trọng hơn process name?
3. Vì sao trusted proxy tạo confused-deputy risk?
4. Vì sao EDR self-protection cần cả PPL và driver/policy?
5. Vì sao LSASS PPL không đủ nếu credential path khác còn mở?
6. Vì sao BYOVD làm PPL threat model xấu hơn?
7. Vì sao PPL bypass thường phụ thuộc build/policy?
8. Vì sao service restart/stop event là detection quan trọng?
9. Vì sao handle telemetry phải gồm cả denied event?
10. Vì sao "PPL abuse" nên được ghi như trust-boundary note, không phải recipe?

## 13. Defender/AMSI/Process Injection Posts

Sources:

- https://core-jmp.org/2026/06/bypassing-windows-defender-amsi-defense-evasion-red-team-guide/
- https://core-jmp.org/2026/05/patchless-amsi-bypass-via-page-guard-exceptions/
- https://core-jmp.org/2026/05/process-injection-without-the-usual-red-flags-abusing-windows-primitives-to-outsmart-classic-edr-telemetry/
- https://core-jmp.org/2026/05/apc-tandem-a-primitive-chaining-process-injection-that-slips-past-common-edr-triggers/

Ý chính: nhóm này quá operational để nhập chi tiết. Giá trị học nằm ở việc hiểu detection pressure: attacker tránh API/hook phổ biến, đổi primitive, đổi timing, đổi memory permission, đổi ancestry.

Giữ lại trong repo:

- Taxonomy injection: allocation, write, permission change, execution trigger, module load, thread/APC.
- Telemetry: process access rights, cross-process memory event, image load, thread start, ETW, AMSI result, script block, command line, parent/child.
- Invariant: muốn chạy code trong context khác thì vẫn phải tạo execution path và memory/materialize content ở đâu đó.
- Mitigation: ASR, WDAC, constrained language, script logging, AMSI health, ETW health, EDR tamper protection.

Không giữ:

- Bypass recipe.
- Patch bytes.
- Function hook removal sequence.
- Payload generation.
- Shellcode launcher.
- Hardware breakpoint/VEH step-by-step.

Câu hỏi "vì sao":

1. Vì sao attacker đổi API nhưng không thể xóa invariant execution?
2. Vì sao AMSI bypass không đồng nghĩa EDR bypass?
3. Vì sao ETW tamper phải tạo health signal?
4. Vì sao process access right nhỏ vẫn có thể đáng ngờ theo context?
5. Vì sao memory permission transition RW -> RX là signal mạnh nhưng không đủ?
6. Vì sao APC/threadpool/callback execution vẫn để lại scheduling artifact?
7. Vì sao allowlisting giảm giá trị của injection chain?
8. Vì sao script telemetry và binary telemetry cần correlate?
9. Vì sao "undetected on AV" không có nghĩa là undetectable?
10. Vì sao detection nên bắt primitive sequence thay vì API name đơn lẻ?

## 14. Shadow SSDT and Win32k Surface

Sources:

- https://core-jmp.org/2026/05/shadow-ssdt-hijacking-achieving-kernel-code-execution-via-read-write-primitives/
- https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-windows-drivers

Ý chính: Shadow SSDT/win32k là vùng giao nhau giữa GUI subsystem và kernel execution. Đọc để hiểu vì sao arbitrary kernel R/W có thể được chuyển thành control-flow impact nếu có target dispatch table/function pointer phù hợp. Không nhập hijack recipe.

Cơ chế cần hiểu:

- Windows có syscall path cho core kernel và GUI/win32k surface.
- Dispatch table/function pointer là control boundary.
- PatchGuard/KCFG/HVCI làm nhiều target cũ không còn dễ dùng.
- GUI syscall thường phụ thuộc process có Win32k context/session, nên precondition rất quan trọng.

Đọc như researcher:

- Ghi rõ target table/function thuộc module nào.
- Ghi mitigation state: PatchGuard, KCFG, HVCI, session isolation.
- Hỏi primitive có cần write-what-where ổn định hay chỉ transient write.

Câu hỏi "vì sao":

1. Vì sao win32k là attack surface lớn dù không phải driver vendor?
2. Vì sao GUI subsystem có syscall table riêng?
3. Vì sao arbitrary R/W chưa tự động là code execution?
4. Vì sao dispatch pointer là target hấp dẫn?
5. Vì sao PatchGuard/KCFG thay đổi lựa chọn target?
6. Vì sao session/process context ảnh hưởng win32k path?
7. Vì sao transient modification vẫn có forensic risk?
8. Vì sao defender nên monitor vulnerable driver trước khi monitor table write?
9. Vì sao exploit note phải tách primitive và post-primitive conversion?
10. Vì sao build-specific validation bắt buộc?

## 15. Windows Early Boot Configuration

Sources:

- https://core-jmp.org/2026/05/windows-early-boot-configuration-the-cmcontrolvector-and-pspsystemmitigationoptions/

Ý chính: mitigation không xuất hiện "ma thuật" sau khi user process chạy. Nhiều policy được đọc trong early boot, ghi vào global state, rồi ảnh hưởng process creation và security flags sau đó.

Cơ chế cần hiểu:

- Registry/control set được đọc sớm.
- Kernel global variables/cache giữ mitigation state.
- Process creation path consult policy để set mitigation behavior.
- Early boot state khó thay đổi an toàn sau khi system đã chạy.

Đọc như researcher:

- Ghi timeline: boot config -> kernel init -> global options -> process creation.
- Hỏi biến nào documented, biến nào internal, biến nào chỉ thấy qua symbol/reverse.
- So sánh với VBS/HVCI/CI policy: nhiều mitigation có root ở boot trust.

Câu hỏi "vì sao":

1. Vì sao mitigation policy phải được quyết định sớm?
2. Vì sao registry state cần được chuyển thành kernel global state?
3. Vì sao changing policy runtime khó và nguy hiểm?
4. Vì sao process creation là điểm áp mitigation?
5. Vì sao boot chain trust ảnh hưởng user-mode security?
6. Vì sao symbol/reverse cần thiết để hiểu internal option?
7. Vì sao forensic cần biết policy lúc boot, không chỉ lúc incident?
8. Vì sao Secure Boot/VBS làm early tamper khó hơn?
9. Vì sao test mitigation cần cold boot, không chỉ restart process?
10. Vì sao build drift có thể đổi tên/ý nghĩa internal flag?

## 16. DIY EDR From Scratch

Sources:

- https://core-jmp.org/2026/05/building-a-diy-edr-from-scratch-windows-kernel-callbacks-user-mode-hooks-and-shellcode-injection-detection/
- https://github.com/microsoft/Windows-driver-samples
- https://learn.microsoft.com/en-us/windows-hardware/drivers/

Ý chính: bài DIY EDR hữu ích nếu đọc như architecture exercise. Nó giúp hiểu các lớp telemetry của một EDR nhỏ: kernel callback, user-mode hook, image/static scan, process/memory event. Không nên xem nó như sản phẩm phòng thủ đủ dùng.

Cơ chế cần hiểu:

- Kernel callback thấy process/thread/image/registry ở mức OS event.
- User-mode hook thấy API-level intent nhưng dễ bị bypass/tamper.
- Static scan bắt known pattern, yếu trước packing/obfuscation.
- Detection tốt là correlation nhiều signal, không phải một hook.

Đọc như engineer:

- Tách collector, normalizer, detector, response.
- Thiết kế health signal cho từng collector.
- Ghi false positive/false negative theo primitive.
- Không để response phá system stability.

Câu hỏi "vì sao":

1. Vì sao EDR nhỏ dễ viết demo nhưng khó vận hành thật?
2. Vì sao kernel callback không thay thế user-mode telemetry?
3. Vì sao user-mode hook vẫn hữu ích dù dễ bypass?
4. Vì sao health monitoring quan trọng ngang detection?
5. Vì sao response trong kernel dễ gây outage?
6. Vì sao static signature phải đứng sau behavior correlation?
7. Vì sao event normalization là phần khó?
8. Vì sao false positive cost quyết định rule design?
9. Vì sao tamper protection là product feature riêng?
10. Vì sao lab EDR giúp hiểu attacker pressure?

## 17. How To Continue

Các bài nên tách thành tài liệu riêng nếu muốn mở rộng repo:

1. `windows-ipc-boundary-atlas.md`: named pipes, ALPC, RPC, COM, DCOM, URL handler.
2. `kernel-callback-telemetry-and-tamper-model.md`: process/thread/image/registry callbacks, callback health, PatchGuard/HVCI interaction.
3. `windows-rpc-fuzzing-lab-safe-workflow.md`: interface discovery, IDL, opnum labeling, ETW/canary/replay.
4. `windows-url-handler-and-ntlm-coercion.md`: protocol handler, shell parsing, outbound auth, egress mitigation.
5. `kernel-offset-versioning-and-symbol-workflow.md`: PDB identity, patch diff, BinDiff, VM build pinning, LLM quality gates.

Review checklist cho mỗi bài core-jmp mới:

```text
1. Có upstream source không?
2. Upstream có phải primary research không?
3. Primitive là gì?
4. Preconditions là gì?
5. Build/version nào?
6. Mitigation nào thay đổi kết quả?
7. Telemetry nào thấy được?
8. Có phần operational cần cắt không?
9. Có câu hỏi "vì sao" đủ để học sâu không?
10. Có lab-safe validation không?
```

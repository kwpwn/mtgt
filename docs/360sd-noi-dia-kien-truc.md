# Tổng quan 360杀毒 / 360SD nội địa: process, quyền chạy, driver và self-protection

> Resource này tách riêng **360杀毒 / 360SD** khỏi **360安全卫士 / Safeguard**. 360SD là sản phẩm antivirus thuần hơn: scan, realtime protection, cloud/QVM/signature/script engines và proactive defense dùng chung họ thành phần với Safeguard.
>
> Mục tiêu là map process/driver/quyền/self-protection để làm lab research và detection engineering. Không phải hướng dẫn tắt hoặc bypass sản phẩm.

Updated: 2026-06-02

## 0a. Tong Quan Rieng: 360SD / 360杀毒

`360SD` la cach goi ngan cua **360杀毒**, tuc san pham antivirus noi dia cua 360. Khac voi `360安全卫士`, 360SD tap trung vao:

- virus/trojan scan,
- realtime file protection,
- proactive defense / `木马防火墙`,
- cloud reputation,
- local engines nhu QVM/QVM II, heuristic, QEX, KunPeng/Behavioral script engine tuy doi,
- update virus database/program.

No **khong phai** suite system-management day du nhu 360Safe. Neu cai chung voi 360Safe, hai san pham co the chia se mot so thanh phan active defense, cloud engine va driver kernel. Khi viet resource, nen tach nhu sau:

| Lop | 360SD lam gi | Khac voi 360Safe |
|---|---|---|
| Main AV UI | `360sd.exe` quan ly giao dien scan, ket qua, settings | Safeguard dung `360Safe.exe` lam suite shell |
| Realtime monitor | `360rp.exe`/`360rps.exe` theo doi file access va ingress tu USB/download/chat/mail | Safeguard co them tray/suite modules va nhieu system utility |
| Proactive defense | `ZhuDongFangYu.exe`/`木马防火墙` bao ve vung he thong nhay cam | Dung chung philosophy voi Safeguard |
| Cloud/security engines | 360云安全中心, QVM/QVM II, QEX, KunPeng/heuristic/local engines | 360Safe co them detection cho software manager, system repair, WiFi/router, patch/vuln |
| Kernel enforcement | Minifilter/object callbacks/ELAM/network drivers tuy bundle | Driver split phai verify tren install thuc te; khong suy tu ten process |

Nguon nen uu tien cho phan detection cua 360SD:

- 360杀毒 privacy v2 noi realtime protection monitor file access, co 3 cap do, bao ve USB/download/chat/mail, va upload unknown file neu join cloud scan plan: https://www.360.cn/privacy/v2/360shadu.html
- 360杀毒 privacy v3 noi cloud center query file/software/URL metadata, `360安全防护中心` trigger theo sensitive behavior, web shield query URL/DNS/host/MD5: https://www.360.cn/privacy/v3/360shadu.html
- 360杀毒 operation guide noi download/chat protection auto-scan received/downloaded files and classify safe/infected/unknown: https://sd.360.cn/es_archive.html

## 0. Kết Luận Nhanh

| Câu hỏi | Câu trả lời ngắn |
|---|---|
| Process chính của 360SD? | `360sd.exe`, `360rp.exe`, `360rps.exe`, thường thấy thêm `360tray.exe` và `ZhuDongFangYu.exe` nếu proactive defense/Safeguard component được cài chung |
| `360sd.exe` làm gì? | GUI / interface management / scan entrypoint; có thể là installer nếu file lấy từ download package |
| `360rp.exe` làm gì? | Realtime protection / realtime monitor; nguồn Trung Quốc mô tả là `360杀毒软件实时监控程序` |
| `360rps.exe` làm gì? | Realtime protection service/helper của 360SD; ít nguồn tốt hơn `360rp.exe`, thường nằm trong `...\360\360sd\` |
| Chạy quyền gì? | `360sd.exe` thường là user-session GUI; `360rp.exe`/`360rps.exe` nhiều khả năng là background service/service-helper, cần lab verify token cụ thể. Enforcement thật nằm ở kernel driver/minifilter, không chỉ token user-mode |
| Có PPL không? | Chưa có nguồn công khai xác nhận 360SD process chạy `AntimalwareLight`; phải verify bằng `_EPROCESS.Protection` hoặc service launch-protection |
| Self-protection bảo vệ gì? | Process, file, registry, driver/system sensitive areas; realtime file access; startup/sensitive behavior; cloud verdict; web/malicious URL; U disk/download/chat/mail file ingress |
| Driver liên quan | `360AvFlt.sys`, `360FsFlt.sys`, `360elam64.sys`, `360Box64.sys`, `BAPIDRV64.sys`, network-related driver tùy bản; legacy `HookPort.sys`/`360SelfProtection.sys` |

## 1. 360SD Là Gì?

360SD là viết tắt cộng đồng của **360杀毒**. Đây là nhánh antivirus, khác với **360安全卫士** là suite hệ thống. Theo Wikipedia zh, 360杀毒 từng tích hợp Bitdefender, 360 Cloud, QVM, system-file repair engine; các bản sau có QVM II, KunPeng, QEX và thay đổi engine theo thời gian. Chức năng chính gồm:

- Virus scan.
- Realtime protection.
- Proactive defense.
- Ad blocking / web protection tùy bản.
- Software cleanup / utilities.
- Virus database and software update.

Nguồn:

- https://zh.wikipedia.org/wiki/360%E6%9D%80%E6%AF%92
- https://www.360.cn/privacy/v2/360shadu.html
- https://www.360.cn/privacy/v3/360shadu.html

## 2. Process Map

| Process | Nhiệm vụ | Quyền chạy / context | Độ chắc |
|---|---|---|---|
| `360sd.exe` | Main UI/scan manager của 360杀毒. Một số file tên này cũng là installer/setup nếu lấy từ download bundle | Thường chạy trong user session khi mở GUI/scan. Nếu là installer thì chạy theo token installer/UAC context | Trung bình: nhiều nguồn xác nhận product/file; quyền cần lab |
| `360rp.exe` | Realtime protection monitor. Nguồn Trung Quốc gọi là `360杀毒软件实时监控程序`, theo dõi hệ thống để chặn malware sớm | Thường là background autorun/service-like process; nguồn nói không thể kill bằng Task Manager khi self-protection bật. Token cụ thể cần Process Explorer/lab | Khá: nguồn Trung Quốc + file.net |
| `360rps.exe` | Realtime protection service/helper. Thường nằm trong `C:\Program Files (x86)\360\360sd\` hoặc `C:\Program Files\360\360sd\` | Không có cửa sổ; có thể monitor programs theo file.net. Token cụ thể cần lab | Trung bình-thấp: nguồn metadata/process DB, ít official |
| `360tray.exe` | Tray / realtime protection UI; ở Safeguard là 木马防火墙/safemon module, nhưng cũng hay xuất hiện cùng 360SD | User session tray, giao tiếp với service/driver | Khá: nhiều process inventory |
| `ZhuDongFangYu.exe` | 360主动防御服务 / proactive defense service, dùng chung hệ 360. Bảo vệ hành vi, file audit, active defense | Nguồn cũ mô tả là service process; token phải verify. Thường được protected bởi driver/callback | Khá: nguồn đổi tên + metadata + threat intel |
| `360rp.exe` / `360rps.exe` / `360sd.exe` trong malware process lists | Process mà malware hay cố terminate để làm yếu AV | Không dùng để kết luận quyền; dùng để xây watchlist | Khá cho process name, không phải internals |

## 2b. Process Va Quyen Chay: Cach Ghi Ngan Gon

| Process | Nhiem vu | Quyen/context hop ly | Diem can verify |
|---|---|---|---|
| `360sd.exe` | GUI/scan manager; doi khi la installer neu file lay tu download package | User-session process hoac elevated installer context | Check `OriginalFileName`, path, parent, command line |
| `360rp.exe` | `360杀毒 实时监控`; realtime monitor bat buoc cua 360SD theo nhieu bai Trung Quoc | Background service-like process; likely protected; exact token can vary | `tasklist /svc`, Process Explorer `User Name`, service `360rp` neu co |
| `360rps.exe` | Realtime protection service/helper candidate | Background/no-window helper; likely service context on some builds | Service mapping, signer, install path `...\360\360sd\` |
| `360tray.exe` | Tray/protection UI when Safeguard/shared protection installed | Logged-on user session | Path often `...\360Safe\safemon\`; may not exist in 360SD-only minimal install |
| `ZhuDongFangYu.exe` | Proactive defense / HIPS service shared by 360 family | Service/background; some old reports show SYSTEM, current build must be measured | PPL vs ObCallback must be separated |
| Kernel drivers | File, process, boot, network enforcement | Ring 0 | `fltmc`, `driverquery`, service registry |

Best current wording:

```text
360sd.exe = user-facing AV UI/scan manager.
360rp.exe / 360rps.exe = realtime protection monitor/service-helper.
ZhuDongFangYu.exe = shared proactive-defense service.
Kernel drivers = actual enforcement for file/process/self-protection.
PPL = unknown unless measured per build.
```

### Ghi chú về `360sd.exe`

Tên `360sd.exe` có hai nghĩa theo context:

```text
installed product process:
  360sd.exe = GUI / antivirus scan manager

downloaded setup package:
  360sd.exe = 360杀毒 installer / setup executable
```

Ví dụ herdProtect thấy một `360sd.exe` signed by Qihoo là `360 杀毒 安装程序`, original filename `Setup.exe`, tải từ `down.360.cn`. Vì vậy khi lab phải xem **path + signer + original filename + command line**, không chỉ tên process.

Nguồn:

- https://www.herdprotect.com/360sd.exe-20a34e67992256955de8aa7b768ce162d339b3a1.aspx

### Ghi chú về `360rp.exe`

Nguồn Trung Quốc 300.cn mô tả `360rp.exe` là một phần của 360杀毒, định nghĩa là realtime monitor, nhiệm vụ là realtime protection chống trojan/virus/malware. Trang này cũng nêu process thường có autostart, path thường ở `C:\360sd\360rp.exe` hoặc thư mục cài 360SD, và Task Manager có thể báo access denied khi self-protection bật.

Nguồn:

- https://m.300.cn/itzspd/710223.html
- https://www.file.net/process/360rp.exe.html

### Ghi chú về `360rps.exe`

Nguồn public tốt ít hơn. file.net bản Đức ghi `360rps.exe` thường ở `...\360\360sd\`, không phải Windows core file, signed, không có visible window, có thể monitor programs. Vì vậy nên coi `360rps.exe` là **realtime protection service/helper candidate** cho đến khi verify trên bản cài cụ thể.

Nguồn:

- https://www.file.net/prozess/360rps.exe.html
- https://www.freefixer.com/library/file/360rps.exe-131199/

## 3. Quyền Chạy: Cách Ghi Cho Đúng

Không có nguồn Trung Quốc công khai đủ tốt nói rõ từng process của 360SD chạy token nào trên mọi version. Vì vậy ghi theo ba lớp:

| Process | Mặc định hợp lý | Cách verify |
|---|---|---|
| `360sd.exe` | User-session GUI hoặc elevated installer tùy context | Process Explorer: User, Integrity, command line, parent |
| `360rp.exe` | Background protection process, có thể service context; self-protected | Process Explorer: User, service mapping; `sc query`, `tasklist /svc` |
| `360rps.exe` | Service/helper/background process | Process Explorer + service mapping |
| `360tray.exe` | Logged-on user tray | Process Explorer: User session, parent |
| `ZhuDongFangYu.exe` | Service/proactive-defense context; thường được bảo vệ | `services.msc`, `sc qc`, Process Explorer token |
| Kernel drivers | Ring 0 | `driverquery`, `fltmc`, WinObj |

Lab checklist:

```text
Process Explorer columns:
  User Name
  Integrity Level
  Command Line
  Verified Signer
  Protection

Service mapping:
  tasklist /svc /fi "imagename eq 360rp.exe"
  tasklist /svc /fi "imagename eq 360rps.exe"
  sc query type= service state= all | findstr /i "360 rp rps sd"
```

PPL check:

```text
sc qprotection <service>
kernel debugger: dt -r1 nt!_EPROCESS <process> and inspect _PS_PROTECTION
```

If `360rp.exe` cannot be killed, do not assume PPL. It may be protected by `ObRegisterCallbacks`/minifilter/driver policy that strips terminate/write rights.

## 4. Realtime Protection Flow

360’s own 360杀毒 privacy whitepaper says realtime protection monitors file access while the machine is on. It describes three levels:

- Highest: monitor all operations on all accessed files.
- Medium/low: monitor more dangerous file-access patterns.
- Additional ingress protection for U disk, download tools, chat tools, and mail programs.

High-level model:

```text
file access / download / chat received file / USB file / mail attachment
  -> realtime monitor process
  -> minifilter / kernel driver sees file operation
  -> local engine + cloud/QVM verdict
  -> allow / scan / block / quarantine / prompt
```

Source:

- https://www.360.cn/privacy/v2/360shadu.html

## 4b. Detection Methods Rieng Cua 360SD

360SD nen duoc mo ta nhu mot AV cloud-centric co realtime file monitor. Cac phuong phap detect chinh:

| Detection method | 360 official/source says | Practical mapping |
|---|---|---|
| Realtime file monitoring | v2 privacy page noi realtime protection mac dinh bat va background-monitor file access khi may dang bat; mode cao nhat monitor moi operation tren moi accessed file, mode medium/low chi monitor dangerous access | `360rp.exe`/`360rps.exe` + minifilter drivers; good place to observe with Procmon/fltmc |
| Ingress protection | v2 page va operation guide noi bao ve USB, download tools, chat tools, mail; files received by QQ/MSN/AliWangWang or downloaded by Xunlei/Kuaiche are auto-scanned | Hook/monitor around download/chat/USB entry points, then file scan/cloud verdict |
| Manual scan modes | Quick scan, full scan, selected location scan, right-click scan; quick scan covers startup programs, desktop, Windows system dir, Program Files; full scan covers boot area, memory and all disk files | `360sd.exe` UI triggers local engine + cloud lookup; right-click shell integration is separate surface |
| Cloud reputation | v3 page says 360 cloud center uses file/software/URL metadata and AI to determine safety; queries include filename, path, publisher/version/signer, run parameters, fingerprint, URL/host/MD5 | Strongest online verdict layer; offline mode loses new-sample/cloud reputation strength |
| Unknown-file upload | v2/v3 pages say if user agrees to auto upload suspicious/unknown files, suspicious executable files, SWF or suspicious scripts in sensitive/startup locations can be uploaded | Lab network should log DNS/TLS metadata; do not assume protocol content without decrypt/RE |
| Sensitive behavior / HIPS | v3 page says embedded `360安全防护中心` is triggered by sensitive behavior, validates executable/file legality through cloud engine, then prompts and suspends suspicious behavior | `ZhuDongFangYu.exe` + driver callbacks; this is behavior detection, not static signature only |
| Web shield / 网盾 | v3 page says web safety protection identifies/warns/blocks pages containing trojans and sends visited URLs, links, title, DNS records to cloud engine | Browser/network layer, likely shared with Safeguard network drivers if installed |
| Cloud security plan | `360云安全计划` says 360Safe and 360SD ask at first install whether to join; suspicious samples may be reported; cloud black/white databases replace heavy local-only comparison | Explains why blocking network hurts detection but local realtime/signature/HIPS still remain |

High-level pipeline:

```text
file access / USB / download / chat file / mail attachment / URL / sensitive behavior
  -> realtime monitor or shell/browser/network hook
  -> minifilter/kernel event where applicable
  -> local cache/signature/QVM/QEX/heuristic
  -> 360云安全中心 reputation query or sample upload if enabled
  -> allow, block, clean, delete/quarantine, prompt, or log
```

What 360SD **does not** cover as its own primary mission:

- patch/vulnerability repair as a full suite workflow,
- software manager/update marketplace,
- cleanup/optimization/user-facing system toolbox,
- document assistant/office workflow features.

Those belong mainly to 360Safe/Safeguard, though shared components may appear when both are installed.

## 5. Cloud, Scan, Upload Scope

360SD supports:

- Quick scan.
- Full scan.
- Custom location scan.
- Right-click scan.
- Scheduled scan if configured.

The v2 whitepaper says quick scan covers startup programs, desktop files, Windows system directory and Program Files; full scan covers boot area, memory and all disk files; custom scan covers selected locations.

If user joins cloud scan plan, unknown files may be uploaded for analysis. The source says executable programs and non-PE files in startup locations can be uploaded. The v3 privacy policy adds details: file name, path, publisher/signature/version/product, run parameters, file fingerprint, URL/host/MD5 and similar metadata may be queried against cloud security.

Sources:

- https://www.360.cn/privacy/v2/360shadu.html
- https://www.360.cn/privacy/v3/360shadu.html
- https://www.360.cn/privacy/v2/yunanquan.html

## 6. 主动防御 / 木马防火墙

360SD realtime protection includes the 360 proactive-defense module, described by 360 as **360木马防火墙**. The privacy whitepaper says it prevents malware from maliciously modifying key system areas and can intercept malicious/phishing websites.

360 general help defines 主动防御 as behavior analysis for trojan/malware combined with cloud scan. It explicitly lists "4D" protection:

| Protection | Meaning |
|---|---|
| 注册表防护 | Registry protection |
| 文件防护 | File protection |
| 进程防护 | Process protection |
| 驱动防护 | Driver protection |

This is the cleanest public answer to "self-protection/proactive defense protect cái gì?": at product-policy level it protects registry, files, processes and drivers; for 360SD specifically it is tied into realtime protection and cloud verdicting.

Sources:

- https://www.360.cn/privacy/v2/360shadu.html
- https://www.360.cn/about/help.html

## 7. Self-Protection: Protects What?

Self-protection has two meanings:

### A. Product self-protection

Protects 360’s own:

- Processes: `360sd.exe`, `360rp.exe`, `360rps.exe`, `360tray.exe`, `ZhuDongFangYu.exe` depending installed bundle.
- Files/directories: 360 install path, engine/signature/config files.
- Registry/service keys: autostart, service configuration, product policy, shell/menu hooks.
- Drivers: minifilter/protection driver load state and service registration.

Public evidence:

- `360rp.exe` source says Task Manager termination may return access denied under self-protection.
- Historical Win64 RE says `360FsFlt.sys` participates in process self-protection and strips dangerous handle rights.
- 360 help says proactive defense includes process/file/registry/driver protection.

### B. System protection

Protects system/user environment from malware:

- File access and infection.
- Startup/sensitive system locations.
- Registry modification.
- Process creation and suspicious behavior.
- Driver loading / plugin installation according to cloud-security plan.
- Malicious/phishing web pages.
- USB/download/chat/mail file ingress.

Cloud security plan says risky operations such as loading drivers and installing plugins can be checked online when using 360 proactive defense / 360SD realtime protection.

Source:

- https://www.360.cn/privacy/v2/yunanquan.html

## 8. Drivers Related To 360SD

Local IDA reverse notes for the 360 driver corpus are in `docs/360-driver-ida-reverse-notes.md`. Those notes give stronger binary-backed role assignments for `360FsFlt`, `360Box64`, `360netmon`, `360Hvm64`, `360elam64`, `360qpesv64`, and the network protection drivers than generic process/database pages.

| Driver | Role | Confidence |
|---|---|---|
| `360AvFlt.sys` | AV minifilter / realtime scan path | High from forensic logs and product role |
| `360FsFlt.sys` | File-system filter + self-protection/object callback behavior | High for existence, RE-backed for internals |
| `360elam64.sys` | ELAM boot-time antimalware component | High for existence in logs; PPL use still unproven |
| `360Box64.sys` | Sandbox/isolation minifilter | Medium-high when sandbox installed |
| `BAPIDRV64.sys` | Kernel helper/bridge; exact IOCTL unknown | Medium |
| Network driver / `360netmon*` / `360AntiHacker*` | Web/network protection | Version-dependent |
| `HookPort.sys`, `360SelfProtection.sys` | Legacy x86-era self-protection/hook architecture | Historical only |

The 360SD-specific public process sources do not fully enumerate drivers. In practice, 360SD and Safeguard share protection layers; enumerate on a real install:

```text
fltmc filters
driverquery /v | findstr /i "360 qh qihoo"
sc query type= driver state= all | findstr /i "360 qh"
```

## 9. PPL Status

No reliable Chinese source found that proves `360sd.exe`, `360rp.exe`, or `360rps.exe` runs as Windows Protected Process Light.

What can be said:

- 360 has ELAM-related driver names in real-world inventories (`360elam64.sys`).
- Windows antimalware PPL requires ELAM certificate registration and launch-protected service configuration.
- Access denied on process termination can be caused by product driver self-protection without PPL.

So write:

```text
PPL: unknown / must verify per build
self-protection: yes, driver-backed behavior is publicly documented/observed
```

## 10. Threat-Intel Watchlist

Antiy’s Chinese report on PowerShell-spread malware lists process names attackers attempted to terminate, including:

```text
360sd.exe
360tray.exe
360safe.exe
360rp.exe
360rps.exe
ZhuDongFangYu.exe
```

This strongly supports the watchlist for both 360SD and Safeguard. It does not prove protection internals, but it shows which process names malware authors considered valuable.

Source:

- https://www.antiy.com/response/MSShell/Analysis_of_several_events_that_use_PowerShell_to_transmit_malware.pdf

## 10b. Chinese Source-Mining Leads

Chinese-only search terms used:

```text
360杀毒 进程 360sd.exe 360rp.exe 360rps.exe 实时监控 服务 权限
360杀毒 操作指南 实时防护 下载工具 聊天软件 防护
360杀毒 隐私 白皮书 实时防护 三个级别 文件系统防护
结束带有进程保护的360杀毒软件实时监控进程
360杀毒 主动防御 实时防护 云查杀 QVM
```

Useful sources from that pass:

| Source | What it adds | How to use it |
|---|---|---|
| 360SD privacy v2 | Realtime protection monitors file access while the machine is on; three protection levels; USB/download/chat/mail protection; unknown-file upload if cloud plan enabled | Strong official source for realtime detection behavior |
| 360SD privacy v3 | Cloud center query fields: filename, path, publisher/version/signer, run parameters, fingerprint, URL/host/MD5; sensitive behavior triggers `360安全防护中心`; web shield URL/DNS collection | Strong official source for cloud/HIPS/web detection surfaces |
| 360 Cloud Security Plan | Explains black/white cloud DB model and sample reporting during scan/realtime protection | Strong official source for cloud-centric architecture |
| `sd.360.cn/support.html` | Product support page says 360SD integrated five engines: BitDefender, Avira, cloud scan, proactive defense, QVM AI | Historical/product source; engine mix changes by version |
| `sd.360.cn/support3.html` | Operation guide: realtime protection and manual scan; quick/full/specified/common-tools scan workflows | Good user-facing behavior source |
| `sd.360.cn/es_archive.html` | Download/chat protection auto-scans received/downloaded files and classifies safe/infected/unknown | Good ingress-protection source |
| CSDN forum `结束带有进程保护的360杀毒软件实时监控进程` | Old forum states 360SD has `360rp.exe` for realtime monitor and `360sd.exe` as UI/scan program | Old forum, useful process-role corroboration only |
| 300.cn `360rp.exe` and `360sd.exe` process notes | Repeats `360rp.exe` as realtime monitor and `360sd.exe` as UI/manager | Low-medium confidence process clue; not internals |
| Chinese Wikipedia `360杀毒` | Historical engine timeline: BitDefender/cloud/QVM/system repair in 2.0; QVM II and later KunPeng/QEX updates; high-level feature list | Good history summary, not primary technical proof |

Practical conclusion from Chinese sources:

```text
360SD detection = realtime file monitor + manual scan + ingress protection
                  + cloud reputation + local/QVM/QEX/heuristic engines
                  + shared proactive defense for sensitive behavior.

360SD process split = 360sd.exe as UI/scan manager,
                      360rp.exe as realtime monitor,
                      360rps.exe as service/helper candidate,
                      ZhuDongFangYu.exe when shared proactive defense is present.
```

Links:

- 360SD privacy v2: https://www.360.cn/privacy/v2/360shadu.html
- 360SD privacy v3: https://www.360.cn/privacy/v3/360shadu.html
- 360 Cloud Security Plan: https://www.360.cn/privacy/v2/yunanquan.html
- 360SD support/index: https://sd.360.cn/support.html
- 360SD scan guide: https://sd.360.cn/support3.html
- 360SD download/chat protection guide: https://sd.360.cn/es_archive.html
- CSDN forum process discussion: https://bbs.csdn.net/topics/330021826
- 300.cn `360rp.exe`: https://m.300.cn/itzspd/710223.html
- 300.cn `360sd.exe`: https://m.300.cn/itzspd/710224.html
- Chinese Wikipedia `360杀毒`: https://zh.wikipedia.org/wiki/360%E6%9D%80%E6%AF%92

## 11. What Is Still Unknown

- Exact token/user for `360rp.exe` and `360rps.exe` across current domestic builds.
- Whether any 360SD service is `SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT`.
- Current driver split between 360SD-only install and full 360安全卫士 install.
- Exact protected file/registry/service key list.
- Exact minifilter altitude and object callback registration order.
- Whether `360rp.exe` and `360rps.exe` are both present on current builds or version-dependent.

## 12. Lab Verification Template

| Question | Command/tool |
|---|---|
| Which processes exist? | Process Explorer, `tasklist /v | findstr /i "360"` |
| Which account runs each process? | Process Explorer `User Name`, `whoami /all` for service session context |
| Which service maps to process? | `tasklist /svc`, `sc query`, `services.msc` |
| Which process is protected/PPL? | Process Explorer Protection column, kernel debugger `_EPROCESS.Protection` |
| Which drivers are loaded? | `fltmc filters`, `driverquery /v`, `sc query type= driver` |
| Which files are protected? | Procmon in VM; try harmless create/rename/read test under install path |
| Which registry keys are watched? | Procmon registry filters on `HKLM\Software\360*`, service keys |
| Which cloud calls happen? | DNS/TLS metadata only; do not assume protocol content |

## 13. Source Map

**Chinese official / product**

- 360杀毒 privacy whitepaper v2:
  https://www.360.cn/privacy/v2/360shadu.html
- 360杀毒 privacy policy v3:
  https://www.360.cn/privacy/v3/360shadu.html
- 360杀毒 operation guide / download-chat protection:
  https://sd.360.cn/es_archive.html
- 360 Cloud Security Plan:
  https://www.360.cn/privacy/v2/yunanquan.html
- 360 help: 主动防御 / 木马云查杀:
  https://www.360.cn/about/help.html

**Chinese encyclopedia / public**

- Wikipedia zh 360杀毒:
  https://zh.wikipedia.org/wiki/360%E6%9D%80%E6%AF%92
- 300.cn `360rp.exe` process note:
  https://m.300.cn/itzspd/710223.html
- Jisuxz `360rp.exe` process/service note:
  https://www.jisuxz.com/article/wenda/4250.html
- 300.cn `360sd.exe` process note:
  https://m.300.cn/itzspd/710224.html

**Process metadata**

- file.net `360rp.exe`:
  https://www.file.net/process/360rp.exe.html
- file.net `360rps.exe`:
  https://www.file.net/prozess/360rps.exe.html
- FreeFixer `360rps.exe`:
  https://www.freefixer.com/library/file/360rps.exe-131199/
- herdProtect `360sd.exe` installer metadata:
  https://www.herdprotect.com/360sd.exe-20a34e67992256955de8aa7b768ce162d339b3a1.aspx

**Threat intelligence**

- Antiy PowerShell malware report:
  https://www.antiy.com/response/MSShell/Analysis_of_several_events_that_use_PowerShell_to_transmit_malware.pdf

**Related repo resources**

- `docs/360-safeguard-noi-dia-kien-truc.md`
- `docs/360-kien-truc-ky-thuat.md`

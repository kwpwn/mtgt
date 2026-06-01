# Mổ xẻ 360安全卫士 nội địa: kiến trúc, process, driver và self-protection

> Resource này tập trung vào **360安全卫士 / 360 Safeguard bản Trung Quốc nội địa**. Đây là suite lớn hơn 360杀毒/360SD: có lõi AV/HIPS dùng chung, nhưng thêm module hệ thống như vá lỗ hổng, phần mềm quản gia, chống ransomware, network shield, tối ưu và cứu hộ.
>
> Mục đích là hiểu kiến trúc và điểm cần kiểm chứng trong lab, không phải hướng dẫn vô hiệu hóa sản phẩm.

Updated: 2026-06-02

## 0a. Tong Quan Rieng: 360Safe / 360安全卫士

`360Safe` trong bai nay chi **360安全卫士 ban noi dia Trung Quoc**, khong phai 360SD. No la mot **security suite + system utility suite**: vua co lop diet trojan/virus, vua co lop sua he thong, va lo hong, cleanup, software manager, web/network shield, document/ransomware protection va cac tool "function collection".

Neu viet nhu mot bai tong quan rieng, nen tach no thanh 5 lop:

| Lop | Thanh phan dai dien | Nhiem vu |
|---|---|---|
| UI / suite shell | `360Safe.exe`, `360Tray.exe` | Mo GUI, tray, hien thi canh bao, dieu phoi module nguoi dung thay duoc |
| Proactive defense / HIPS | `ZhuDongFangYu.exe`, `360Tray.exe`, service lien quan | Theo doi hanh vi nhay cam, process/file/registry/driver protection, dua verdict cho user-mode |
| AV and cloud verdict | cloud engine, QVM II, heuristic, QEX, local engine | Scan file, hash/reputation, script detection, malicious URL/software verdict |
| System management | `360leakfixer.exe`, `softmgr.exe`, patch/repair/cleanup tools | Va lo hong, sua cau hinh bi malware sua, quan ly software, startup optimization |
| Kernel enforcement | `360FsFlt.sys`, `360AvFlt.sys`, `360Box64.sys`, `360elam64.sys`, `360Hvm64.sys`, network drivers | File minifilter, object/process protection, sandbox/isolation, boot-time protection, network filtering |

Nguon official 360 2025 privacy page noi rat ro: hon 90% security detection cua 360安全卫士 dua vao `360云安全中心`; san pham thu thap metadata nhu ten file, path, publisher/signature/version, file fingerprint, URL/host/MD5 de hoi cloud verdict. Nguon nay cung mo ta `电脑体检`, `木马查杀`, `系统修复`, `漏洞修复`, `软件管家`, `360安全防护中心`, `WiFi体检`, `功能大全` nhu cac module rieng. Link:

- https://weishi.360.cn/privacy.html

## 0b. Tom Tat Process Va Quyen Chay

| Process | Nhiem vu thuc te | Quyen/context nen ghi | Ghi chu |
|---|---|---|---|
| `360Safe.exe` | Main GUI / `360安全卫士 主程序模块`; dieu phoi suite, scan, repair, settings | Thuong la user-session GUI; khi thao tac can admin co the elevate qua UAC/helper service | Dung path, signer, original filename de phan biet voi file gia mao |
| `360Tray.exe` | Tray + `木马防火墙`/safemon UI, canh bao realtime, shortcut vao protection center | Thuong la logged-on user tray process | Cac bai Trung Quoc mo ta nam duoi `...\360Safe\safemon\`; co network usage |
| `ZhuDongFangYu.exe` | `360主动防御服务模块`; realtime monitor, file audit, proactive defense, smart acceleration | Service/background context; mot so inventory cu thay chay `NT AUTHORITY\SYSTEM`, nhung current build phai verify | Khong ket luan PPL chi vi Task Manager bao access denied |
| `LiveUpdate360.exe` | Update product/engine/signature/cloud config | User/helper/service tuy trigger | Can check parent process va service mapping |
| `360leakfixer.exe` | `漏洞修复`; quet va cai patch Windows/third-party | Thuong can admin/helper service khi cai patch | Official privacy page noi no quet system dirs, registry Windows Update/package keys |
| `softmgr.exe` | `软件管家`; install/update/uninstall software | User GUI + helper elevated khi install/uninstall | User-mode la chinh, nhung cloud query ve software metadata |

Ket luan quyen chay: `360Safe.exe`/`360Tray.exe` la lop user-session de hien thi va dieu khien; enforcement that su nam o service + kernel drivers. `ZhuDongFangYu.exe` nen duoc ghi la **service/proactive-defense process, likely SYSTEM on some builds, must verify per build**. Khong co nguon public du chac noi process nao cua ban noi dia hien tai la `AntimalwareLight` PPL.

## 0. Cheat Sheet

| Hạng mục | Thành phần chính |
|---|---|
| Product | `360安全卫士` / 360 Safeguard, khác `360杀毒` / 360SD |
| Process lõi | `360Safe.exe`, `360Tray.exe`, `ZhuDongFangYu.exe`, `LiveUpdate360.exe` |
| Module Safeguard | 漏洞修复, 软件管家, 系统急救箱, 文档卫士/反勒索, 网盾/网络防护, 加速球 |
| Driver thường gặp | `360AvFlt.sys`, `360FsFlt.sys`, `360Box64.sys`, `360elam64.sys`, `360Hvm64.sys`, `360netmon.sys`/`360netmon_60.sys`, `360AntiHacker64.sys`, `360Camera64.sys`, `BAPIDRV64.sys` |
| Driver đời cũ | `HookPort.sys`, `360SelfProtection.sys` |
| Engine | 360 Cloud/云查, QVM/QVM II, 启发式, QEX, 鲲鹏/KunPeng, BitDefender/Avira tùy bản |
| Self-protection | Object callbacks, minifilter, whitelist/PID tracking, watchdog/process relaunch, ELAM, hypervisor/memory protection |
| PPL | Chưa có nguồn công khai đủ chắc xác nhận process nội địa nào chạy `AntimalwareLight`; phải đo trực tiếp |

Local IDA reverse notes for the driver corpus are in `docs/360-driver-ida-reverse-notes.md`. Prefer that file over generic blog claims when assigning driver roles.

## 1. 360安全卫士 Khác 360SD Ở Đâu?

360SD (`360杀毒`) là sản phẩm diệt virus tập trung vào scan/realtime protection. Process đại diện là `360sd.exe`.

360安全卫士 (`360Safe.exe`) là suite bao trùm hơn:

- 木马查杀 / trojan and malware removal.
- 漏洞修复 / patch and vulnerability repair.
- 电脑体检 / system health check.
- 软件管家 / software management.
- 清理垃圾 / cleanup.
- 网盾 / web and network protection.
- 文档卫士 / document protection against ransomware.

Điểm quan trọng cho nghiên cứu kernel: phần AV/HIPS của Safeguard dùng cùng họ process/driver với 360SD, đặc biệt `ZhuDongFangYu.exe`, `360FsFlt.sys`, `360AvFlt.sys`, `360elam64.sys`, và các module network/minifilter. Khác biệt chính của Safeguard nằm ở các module hệ thống và khôi phục.

Nguồn đối chiếu:

- Wikipedia zh mô tả 360安全卫士 là phần mềm an toàn hỗ trợ trên Windows/Linux/Mac, với chức năng kiểm tra máy, diệt trojan, sửa hệ thống, dọn rác, tối ưu và phần mềm quản gia:
  https://zh.wikipedia.org/wiki/360%E5%AE%89%E5%85%A8%E5%8D%AB%E5%A3%AB
- Wikipedia zh mô tả 360杀毒 là phần mềm antivirus của Qihoo:
  https://zh.wikipedia.org/wiki/360%E6%9D%80%E6%AF%92

## 2. Process Chính

| Process | Vai trò | Ghi chú kiểm chứng |
|---|---|---|
| `360Safe.exe` | GUI/main program của 360安全卫士 | Nhiều malware và sandbox report dùng tên này để nhận diện Qihoo 360 |
| `360Tray.exe` | Tray/realtime protection | file.net ghi path thường gặp trong `...\360\360Safe\safemon\` hoặc `...\360\Total Security\safemon\` |
| `ZhuDongFangYu.exe` | 360主动防御服务 / proactive defense service | Process lõi HIPS, liên quan realtime protection, file audit và smart acceleration |
| `LiveUpdate360.exe` | Update | Cập nhật engine/signature/cloud config |
| `360leakfixer.exe` | 漏洞修复 | Module vá lỗ hổng/hệ thống |
| `softmgr.exe` | 软件管家 | Software manager, user-mode heavy |

### ZhuDongFangYu.exe

Bài Trung Quốc năm 2009 về việc đổi tên process ghi rõ `krnl360svc` được đổi thành `ZhuDongFangYu` vì tên cũ khó hiểu với người dùng Trung Quốc. Bài đó cũng mô tả service này phục vụ realtime protection, file audit, proactive defense và smart acceleration.

FreeFixer metadata mẫu cũ ghi:

- Product name: `360安全卫士`.
- File description: `360主动防御服务模块`.
- Typical path: `C:\Program Files\360\360safe\deepscan\`.
- Signer: Qizhi Software (beijing) Co. Ltd.

Nguồn:

- https://www.hunuo.com/News/hangyexinwen/2530.html
- https://www.freefixer.com/library/file/ZhuDongFangYu.exe-41973/

## 3. Module Đặc Thù Safeguard

| Module | Chức năng | Kernel liên quan? | Độ chắc |
|---|---|---|---|
| 漏洞修复 | Vá lỗ hổng, tải/áp patch, xử lý môi trường hết hỗ trợ như Win7 shield | Có thể có phần system-level hardening/micro-patch | Vendor công bố |
| 文档卫士 | Tự động backup khi phát hiện sửa đổi tài liệu, giữ bản sao 30 ngày theo trang 360 Total Security | Có khả năng dùng driver/file monitor; tên driver cụ thể chưa chắc | Vendor công bố, chưa có RE độc lập |
| 反勒索服务 | Dịch vụ hỗ trợ ransomware; trang 360 nêu quy trình bật dịch vụ và xin hỗ trợ nếu tài liệu bị mã hóa | Chủ yếu service/cloud + local telemetry/backup | Vendor công bố |
| 系统急救箱 | First-aid/rescue toolkit | Có thể thao tác sâu với hệ thống, cần lab riêng | Vendor/module public |
| 软件管家 | Cài/gỡ/cập nhật phần mềm | Chủ yếu user-mode | Public |
| 网盾/网络防护 | Web/network protection, URL and traffic protection | Có, thường gắn với `360netmon*`/`360AntiHacker*` | Driver inventory + vendor |
| 加速球/优化加速 | Dọn RAM/tối ưu/desktop floating UI | Không đáng kể ở kernel | Public |

360 official privacy whitepaper mô tả **安全防护中心** theo các nhóm phòng hộ sau:

| Nhóm | Thành phần vendor nêu | Ý nghĩa research |
|---|---|---|
| Browser protection | Web safety, video-viewing safety, shopping safety, search safety, homepage/default search/default browser protection, mail safety | Tầng browser/default-app/URL policy; dễ sinh nhiều hook/injection/user-mode monitor |
| System protection | Network, camera, keylogger, file-system, driver, process, registry protection | Đây là nhóm kernel/HIPS đáng ưu tiên khi triage driver |
| Entry protection | Chat, download, USB, hacker intrusion, LAN protection | Nối user-mode app events với file/network/device policy |
| Isolation | Isolate suspicious programs | Liên hệ sandbox/minifilter, `360Box64` và policy broker |

Whitepaper cũng nói `360自我保护` kích hoạt khi process/file/registry của sản phẩm bị đụng theo cách nhạy cảm; hành vi được đưa qua cloud engine validation. Đây là nguồn vendor quan trọng vì nó xác nhận phạm vi tự bảo vệ là **process + file + registry**, không chỉ process.

Nguồn 360 Document Protector bản tiếng Trung nêu "发现文档修改后自动备份", giữ bản sao 30 ngày và hỗ trợ tài liệu bị mã hóa:

- https://www.360totalsecurity.com/zh-cn/tools/document-protector/

Trang 360 反勒索服务 nêu quy trình bật dịch vụ trong 360安全卫士 và hỗ trợ khôi phục/tư vấn khi gặp ransomware:

- https://fuwu.360.cn/process.html

Trang 360 privacy whitepaper nói khi bật document protection, 360 quét tài liệu và backup local cần thiết; khi có thay đổi đáng ngờ thì chặn hành động sửa tài liệu và phục hồi từ backup:

- https://www.360.cn/privacy/v2/360anquanweishi.html

Trang 360 功能大全 xác nhận các module user-facing như 系统急救箱, 360网盾, 断网急救箱 và ghi chú tính năng thay đổi theo phiên bản:

- https://weishi.360.cn/gongnengdaquan.html

Trang 360 系统急救箱 mô tả công cụ dùng "多种强力底层技术" để xử lý malware cứng đầu, gồm driver-type và boot-sector malware; dùng khi 360安全卫士/360杀毒 không cài hoặc không khởi động được:

- https://baoku.360.cn/sinfo/221_9510099.html

## 4. Engine Và Cloud-Centric Architecture

360 mô tả hệ sinh thái endpoint theo hướng cloud/big-data/AI. Với bản enterprise endpoint, 360 nêu cơ chế phát hiện phối hợp gồm:

- 云查杀引擎 / cloud scan engine.
- 鲲鹏大数据特征引擎 / KunPeng big-data feature engine.
- QVM II 人工智能引擎.
- QEX 脚本引擎.

Trang 360 endpoint còn mô tả 主动防御 từ nhiều mặt: system protection, browser protection, entry protection, web protection; các kịch bản gồm file access, process creation, registry read/write và device loading.

Nguồn:

- https://360.net/mobile/product-center/Endpoint-Security/management-system

360 cũng quảng bá số liệu "250亿恶意样本", "22万亿安全日志", "80亿恶意域名信息" và dữ liệu trên 2EB cho 360安全大脑. Đây là số vendor công bố, dùng để hiểu mô hình sản phẩm, không nên coi là benchmark độc lập.

Nguồn:

- https://360.net/mobile/about/news/article5e8d5e00931cc2004d3f5ca7
- https://weishi.360.cn/win7shield.html

Privacy whitepaper bổ sung một chi tiết quan trọng cho network layer: vendor nói network protection dùng **high-performance network filtering driver** ở network layer, và có thể đưa URL, DNS name, SMTP sender/recipient hashes, một phần protocol header <= 256 bytes lên cloud để đối chiếu. Đây là nguồn tốt hơn các trang driver database khi mô tả vai trò `360netmon*`.

## 4b. Process And Service Names Seen In Threat Intel

Nhiều báo cáo malware/security dùng tên process 360 làm chỉ báo để detect/kill/né sản phẩm. Đây không phải nguồn internals, nhưng rất hữu ích để xác định "process nào thật sự quan trọng trong thực chiến".

| Source | Process 360 xuất hiện | Ý nghĩa |
|---|---|---|
| Antiy PowerShell malware report | `360sd.exe`, `360tray.exe`, `360safe.exe`, `360rp.exe`, `360rps.exe`, `ZhuDongFangYu.exe` | Danh sách AV-killer cũ nhắm cả 360SD và Safeguard |
| Operation Dragon Castling / VB2022 | `360sd.exe`, `360rp.exe`, `360Tray.exe`, `360Safe.exe`, `360rps.exe`, `ZhuDongFangYu.exe` | APT/malware ecosystem coi đây là process inventory đáng kiểm tra |
| Elastic RONINGLOADER 2025 | `360Safe.exe`, `360Tray.exe`, `ZhuDongFangYu.exe` | Loader dùng kernel driver riêng để terminate Qihoo 360 processes |
| CN-SEC explorer false-positive analysis | `360leakfixer.exe`, `360safe.exe`, `360PatchMgr64.exe`, `360Tray.exe`, `ZhuDongFangYu.exe` | Nhóm process/module Safeguard được code kiểm tra sự hiện diện |
| Dr.Web Trojan.DownLoader12.20462 | `ZhuDongFangYu.exe`, `360tray.exe`, `Hookport.sys`, `360SelfProtection.sys`, `BAPIDRV.SYS`, `360AntiARP.sys`, `EfiMon.sys` | Dữ liệu 2015 về file/service cũ; hữu ích để map legacy component names |

Không dùng các nguồn threat intel này để kết luận cơ chế bảo vệ. Dùng chúng để xây **watchlist** khi lab:

```text
360Safe.exe
360Tray.exe
ZhuDongFangYu.exe
360sd.exe
360rp.exe
360rps.exe
360leakfixer.exe
360PatchMgr64.exe
LiveUpdate360.exe
```

## 5. Driver Inventory Và Vai Trò

| Driver | Loại | Vai trò nghiên cứu | Nguồn/verify |
|---|---|---|---|
| `360AvFlt.sys` | Minifilter | Realtime AV/file scan | `fltmc filters`; BleepingComputer logs |
| `360FsFlt.sys` | Minifilter + self-protection anchor | File protection, object callback/self-protection, whitelist/PID behavior theo RE công khai | `fltmc`; CSDN 2024; BleepingComputer logs |
| `360Box64.sys` | Minifilter/sandbox | Sandbox, liên quan `C:\360SANDBOX` | BleepingComputer logs |
| `360elam64.sys` | ELAM | Early Launch Anti-Malware; điều kiện cần nếu product muốn đăng ký protected antimalware service | Microsoft ELAM docs + driver inventory |
| `360Hvm64.sys` | Hypervisor-like/HVM | Memory protection/晶核 theo RE công khai; nguồn đơn, cần dè dặt | CSDN 2024 |
| `360netmon.sys`/`360netmon_60.sys` | Network monitor | Network/web protection | driverquery; third-party driver DB; product context |
| `360AntiHacker64.sys` | Network/kernel | Network anti-hacker module | BleepingComputer logs/product naming |
| `360Camera64.sys` | Device protection | Webcam protection | BleepingComputer logs |
| `BAPIDRV64.sys` | Kernel helper | User-kernel helper/bridge; IOCTL cụ thể chưa có nguồn chắc | WinObj/driver inventory |
| `360AntiARP.sys` | Legacy/network | Anti-ARP/network protection in older inventories | Dr.Web 2015 inventory; verify per build |
| `EfiMon.sys` | Legacy/boot or EFI monitor | Seen in older service/file inventories; exact role version-specific | Dr.Web 2015 inventory |
| `qutmdrv.sys`/`qutmipc.sys` | Legacy Qihoo/QUTM components | Seen around older deepscan/IPC inventories | Dr.Web 2015 inventory |
| `360rp.sys`/`360sd.sys` | Reported realtime/protection drivers in some CSDN posts | Treat as low-confidence until found on disk/registry; names may refer to service/process family, not current `.sys` | Low-confidence CSDN, verify locally |
| `HookPort.sys` | Legacy hook framework | x86-era syscall interception | old RE sources |
| `360SelfProtection.sys` | Legacy self-protection policy | Policy layer for older HookPort era | old RE sources |

Forensic logs show real machines carrying these drivers. Example BleepingComputer FRST log includes `360AvFlt`, `360Box64`, `360Camera`, `360FsFlt`, and `BAPIDRV64`:

- https://www.bleepingcomputer.com/forums/t/594401/360-total-security-may-have-hosed-my-computer/

Another log includes `360FsFlt` and `BAPIDRV64`:

- https://www.bleepingcomputer.com/forums/t/588455/computer-keeps-changing-proxy-settings-on-its-own/

Dr.Web’s 2015 malware-library entry is useful as a historical file inventory because it lists many old 360 paths and services created/executed by the installer/malware sample, including `ZhuDongFangYu.exe`, `360tray.exe`, `Hookport.sys`, `360SelfProtection.sys`, `BAPIDRV.SYS`, `360AntiARP.sys`, `EfiMon.sys`, `qutmdrv.sys`, and `qutmipc.sys`. Treat it as **legacy-era inventory**, not current-version truth:

- https://vms.drweb-av.de/virus/?i=10760468

## 6. Self-Protection Evolution

### Era 1: x86 HookPort / KiFastCallEntry

Old Chinese RE writeups describe 360 v6-era protection using `HookPort.sys` and `360SelfProtection.sys`, with syscall interception around `KiFastCallEntry` rather than a simple SSDT table patch. The key research point is the split:

```text
HookPort.sys
  -> generic hook/filter framework
360SelfProtection.sys
  -> protection policy
```

This is historical. Do not assume current x64 builds share this model.

### Era 2: x64 PatchGuard Era / ObRegisterCallbacks

On x64, PatchGuard makes old inline-hook patterns fragile. Public RE analysis describes 360 moving to Microsoft-supported object callbacks and minifilter-based protection:

```text
360FsFlt.sys
  -> object callback strips dangerous process/thread handle rights
  -> minifilter protects product files and directories
```

This explains why normal admin tools can see a process but receive access denied or lack terminate/write rights. That symptom alone does **not** prove PPL.

The 2011/2012 CSDN mirror of achillis’ analysis is useful because it gives concrete lab context: Windows 7 x64, 360安全卫士 7.7, and only two loaded 360 drivers observed: `360FsFlt.sys` plus a network-related driver. The author reports `OpenProcess` with low rights can work, but attempts to duplicate or obtain higher-right handles fail. That is consistent with callback-based rights stripping.

Source:

- https://blog.csdn.net/weixin_34032779/article/details/92695834

### Era 3: 360FsFlt Whitelist + 360Hvm64 "晶核"

The CSDN 2024 writeup "杀死那个名为360安全的软件" says:

- `360FsFlt` keeps a whitelist of executables under the 360 install directory.
- Running whitelisted executables causes PID tracking.
- `360Hvm64`/晶核 participates in memory-write protection logic.
- The author claims to have found logic flaws around this model.

Treat this as **single-source RE**. It is useful as a research lead, not a final fact until reproduced in IDA/WinDbg on a known product build.

Source:

- https://blog.csdn.net/2401_83799022/article/details/137875851

## 7. PPL Status

Do not label `360Safe.exe`, `360Tray.exe`, `360sd.exe`, or `ZhuDongFangYu.exe` as PPL unless you have measured it.

What is known:

- 360 has `360elam64.sys` on real installs.
- Windows allows antimalware vendors with an ELAM driver to register protected services.
- Microsoft’s antimalware protected service model uses `SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT`.
- Public Chinese blogs and driver inventories do not conclusively show which 360 internal process, if any, runs as `AntimalwareLight` on current domestic builds.

Lab checks:

| Question | Check |
|---|---|
| Is the service launch-protected? | `sc qprotection <service>` where supported, or SCM `QueryServiceConfig2` |
| Is the process PPL? | Kernel debugger: inspect `_EPROCESS.Protection` |
| Is access denied due to PPL or callbacks? | Compare protection level with handle rights stripped by `ObRegisterCallbacks` |

Microsoft references:

- https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-
- https://learn.microsoft.com/en-us/windows-hardware/drivers/install/early-launch-antimalware

## 8. Detection Flow

High-level flow:

```text
file/process event
  -> minifilter / object callback / network monitor
  -> local metadata and hash extraction
  -> cloud reputation / 360安全大脑
  -> QVM/KunPeng/QEX/signature/heuristic verdict
  -> HIPS behavior policy
  -> block/quarantine/restore/prompt/log
```

Safeguard adds recovery and system-management layers:

```text
ransomware-like document modification
  -> document protection observes modification
  -> local backup / restore path
  -> optional anti-ransomware service workflow
```

This is why blocking network weakens 360 but does not reduce it to zero. Cloud verdicts, live threat intel, updates and ransomware service workflows degrade, but local minifilters, HIPS rules, signatures, and local document backup may still work.

## 8b. Detection Methods Rieng Cua 360Safe

360Safe phai duoc doc nhu mot suite nhieu be mat detect, khong chi "AV scan file". Cac be mat detect quan trong:

| Be mat detect | 360 noi gi | Mapping ky thuat / process-driver |
|---|---|---|
| Cloud reputation | 360 privacy page noi hon 90% security detection cua Safeguard do `360云安全中心` dam nhiem; metadata file/software/URL duoc query len cloud | User-mode engine + cloud client; minifilter/process monitor thu metadata; offline se mat lop verdict nhanh nhat |
| Trojan/malware scan | `木马查杀` scan registry va file; quick scan xem startup folder, Run keys, services, drivers, memory process/module, scheduled tasks; full scan xem tat ca disk PE/non-PE | `360Safe.exe` scan UI, AV engine, `360AvFlt`/`360FsFlt`; script files nhu VBS/VBE/JSE/BAT/CMD la non-PE surface |
| Sensitive behavior / HIPS | `360安全防护中心` bi trigger boi sensitive behavior, validate executable/file legitimacy bang fingerprint/path/features len `360云引擎`; neu suspicious thi prompt va pause behavior | `ZhuDongFangYu.exe` + `360FsFlt` object callbacks/minifilter + registry/process callbacks trong driver corpus |
| Web/network shield | `网页安全防护`/`网盾` canh bao/chan trojan page, phishing; query URL, links, title, DNS record va host/MD5 cloud verdict | `360Tray.exe`/browser hooks + network filtering drivers `360netmon*`, `360AntiHacker*` |
| System repair detection | `常规修复` scan plugin folders, registry/system settings, IE/browser locations, mail client config, desktop/start menu/browser favorites/quick launch high-risk locations | Suite-level repair module; dung de detect persistence/config hijack hon la AV raw |
| Vulnerability repair | `漏洞修复` scan Windows/component/package and software patch state; download/install Microsoft/third-party patches after user choice/auto mode | `360leakfixer.exe`/patch manager; may use service/elevated helper |
| Software safety | `软件管家` va `软件安全检测` doc installed software metadata, unknown software path/features/IP access de cloud analysis | `softmgr.exe`, safety detection module; useful for PUA/bundle/software reputation |
| Document/ransomware protection | `文档卫士` auto-backup when document changes, retain copies; ransomware service/backup/restore workflow | File monitor/minifilter-backed behavior is plausible; exact driver name not confirmed |
| Startup/health check | `电脑体检` doc 360 config + system config: protection autostart, proactive defense status, shopping protection, auto-update, RDP/guest/startup/scheduled tasks | GUI/system module, useful for posture scoring |

Flow doc nen ghi nhu sau:

```text
file / process / URL / registry / driver-load / startup-location event
  -> user-mode module or kernel callback/minifilter captures metadata
  -> local allow/block/cache + cloud query to 360云安全中心
  -> QVM II / heuristic / QEX / anti-ransomware / local signature checks
  -> behavior/HIPS policy for sensitive action
  -> block, quarantine, repair, backup/restore, prompt, or report
```

Nguon chinh:

- 360Safe privacy 2025: https://weishi.360.cn/privacy.html
- 360木马查杀 engine page: https://weishi.360.cn/safe/mmcs/
- 360 Endpoint Security engine/proactive-defense description: https://360.net/product-center/Endpoint-Security/end-safe-system

## 9. 主防 7.0 And "38 Layers"

360’s 2020 主防 7.0 article claims an expanded protection model:

- Existing layers: 11 system protection, 7 browser protection, 9 entry protection, 7 web protection.
- Added 4 advanced-threat layers: advanced attack discovery, lateral movement protection, fileless attack protection, software hijack protection.
- Marketing total: 38 layers.

This is product-positioning language, but it is useful for mapping feature claims to telemetry/lab questions. The four advanced-threat items map to common enterprise EDR/HIPS surfaces: process creation, remote service/task activity, WMI/COM/registry abuse, DLL hijack and memory injection.

Source:

- https://news.safe.360.cn/n/11802.html

## 9b. Source Quality Notes

During expanded source mining, several Chinese CSDN/Q&A pages appeared with suspiciously generic or AI-style content. They mention driver names like `360rp.sys`, `360sd.sys`, `360netflt.sys`, `QVMfime.sys`, or service names like `360RealProtect`. These names may be useful leads, but do **not** promote them to facts without local evidence:

```text
accepted as fact:
  driver/process appears in official docs, forensic logs, signed file metadata,
  or you see it in fltmc/driverquery/registry on a lab install

research lead only:
  name appears only in generic uninstall/how-to/Q&A content
```

Practical handling:

- Keep `360FsFlt`, `360AvFlt`, `360Box64`, `360elam64`, `360Hvm64`, `BAPIDRV64`, `360netmon*`, `360AntiHacker64`, and `360Camera64` in the primary driver table because they have forensic/log or strong context.
- Keep `360rp.sys`, `360sd.sys`, `360netflt.sys`, `QVMfime.sys` as **candidate names to grep for** in a real install, not as canonical driver names.
- Prefer `fltmc`, `driverquery`, service registry, Authenticode signer, and file path over blog prose.

## 9c. Chinese Source-Mining Leads

Search terms used were intentionally Chinese-only, for example:

```text
360安全卫士 进程 360Safe.exe 360Tray.exe ZhuDongFangYu.exe 主动防御 服务 权限
360安全卫士 驱动 360FsFlt 360AvFlt 360Hvm64 主动防御
浅析360在系统的进程自保护及突破 360FsFlt ObRegisterCallbacks
360安全卫士 主动防御 木马防火墙 4D 注册表 文件 进程 驱动 防护
360安全卫士 文档卫士 自动备份 勒索病毒 防护
```

Useful Chinese-language sources found in that pass:

| Source | What it adds | How to use it |
|---|---|---|
| 360 current Safeguard privacy page | Current product surface: cloud center, health check, trojan scan, repair, patching, software manager, protection center, WiFi/router scan, feature collection | Strong vendor source for "what data/surface is inspected", not for kernel internals |
| 360 v2 Safeguard privacy whitepaper | Older but detailed: U-disk autorun checks, suspicious privilege/account behavior, sandbox prompts, document protection backup/restore | Good for mapping historical feature behavior |
| 360 official help `主动防御` | Defines proactive defense and "4D" protection: registry, file, process, driver | Strong concise answer to "protects what?" |
| 360 `木马查杀` page | Six-engine claim: cloud scan, heuristic, QEX, QVM II, Avira/local engine, anti-ransomware engine | Good for engine table; numbers are vendor marketing |
| 360 Endpoint Security page | Cloud/KunPeng/QVM II/QEX and behavior-defense anchors | Enterprise page, useful for common engine naming |
| CSDN/51CTO `浅析360在系统的进程自保护及突破` | Win7 x64 / 360 7.7-era `360FsFlt.sys`, `ObRegisterCallbacks`, process/thread handle monitoring | High-value RE source, old version only |
| CSDN 2024 `杀死那个名为360安全的软件` | Research lead for `360FsFlt` whitelist/PID tracking and `360Hvm64`/`晶核` memory-protection claims | Single-source RE; cite as lead, do not treat as universal current fact |
| 360 `wannacry` / `qiaozha` pages | Ransomware/document protection positioning: document backup, file recovery, anti-ransomware service | Strong for user-facing ransomware/document-protection claims |
| Onlinedown/CSDN reposts about `360Tray.exe` | Repeatedly identify `360Tray.exe` as `360安全卫士 木马防火墙模块` under `safemon` | Low-medium confidence, useful only to corroborate process role/path |

Important handling rule:

```text
official 360 page -> good for product feature/detection surface
Chinese RE blog/forum -> good for version-specific internals leads
Q&A/SEO/tutorial page -> process-name/path clue only
```

Links:

- 360Safe current privacy: https://weishi.360.cn/privacy.html
- 360Safe v2 privacy: https://www.360.cn/privacy/v2/360anquanweishi.html
- 360 official help / 主动防御: https://www.360.cn/about/help.html
- 360 木马查杀: https://weishi.360.cn/safe/mmcs/
- 360 Endpoint Security: https://360.net/product-center/Endpoint-Security/end-safe-system
- CSDN self-protection RE mirror: https://blog.csdn.net/weixin_34032779/article/details/92695834
- 51CTO self-protection RE mirror: https://blog.51cto.com/u_2817071/733465
- CSDN 2024 `360FsFlt`/`360Hvm64` lead: https://blog.csdn.net/2401_83799022/article/details/137875851
- 360 ransomware recovery page: https://www.360.cn/wannacry/
- 360 ransomware/document-protection page: https://www.360.cn/qiaozha/index.html

## 10. What Remains Unknown

- Exact minifilter altitude for each build.
- Which domestic 360 processes are PPL, if any.
- Exact device names and IOCTL contract of `BAPIDRV64.sys`.
- Exact driver/file name behind 文档卫士 kernel-level backup, if separate from existing file filters.
- Current `360Hvm64.sys` VMX/EPT behavior on 2024-2026 builds.
- Cloud protocol endpoint format and encrypted payload details.
- Whether consumer Safeguard and enterprise endpoint share identical driver policy in a given release.

## 11. Lab Verification Checklist

| Goal | Tool |
|---|---|
| Process inventory | Process Explorer / Process Hacker |
| Signature and path | Process properties, `sigcheck` |
| Minifilter list and altitude | `fltmc filters`, `fltmc instances` |
| Driver inventory | `driverquery /v`, `sc query type= driver` |
| Service config | `sc qc <service>`, registry service key |
| PPL/protection level | `sc qprotection`, kernel debugger `_EPROCESS.Protection` |
| Device objects | WinObj under `\Driver` and `\Device` |
| File/registry behavior | Procmon in a throwaway VM |
| Cloud dependency | Wireshark/ETW DNS/TLS metadata, without decrypting proprietary content |

## 12. Source Map

**Vendor / official**

- 360 Safeguard privacy policy/current product data and detection surfaces:
  https://weishi.360.cn/privacy.html
- 360木马查杀 page: six engine list and cloud/security-brain claims:
  https://weishi.360.cn/safe/mmcs/
- 360 Endpoint Security product page: cloud/KunPeng/QVM II/QEX engines and proactive defense coverage:
  https://360.net/mobile/product-center/Endpoint-Security/management-system
- 360 Endpoint Security current product page: cloud/KunPeng/QVM II/QEX and behavior-defense anchors:
  https://360.net/product-center/Endpoint-Security/end-safe-system
- 360 主防 7.0 / 38-layer protection:
  https://news.safe.360.cn/n/11802.html
- 360 Win7 Shield / 360安全大脑 data claims:
  https://weishi.360.cn/win7shield.html
- 360 Document Protector:
  https://www.360totalsecurity.com/zh-cn/tools/document-protector/
- 360 Anti-ransomware service process:
  https://fuwu.360.cn/process.html
- 360 Safeguard privacy whitepaper:
  https://www.360.cn/privacy/v2/360anquanweishi.html
- 360 Safeguard function collection:
  https://weishi.360.cn/gongnengdaquan.html
- 360 System First-Aid Kit listing:
  https://baoku.360.cn/sinfo/221_9510099.html
- 360 WannaCry/ransomware rescue page:
  https://www.360.cn/wannacry/

**Chinese blog/news**

- `krnl360svc` renamed to `ZhuDongFangYu.exe`:
  https://www.hunuo.com/News/hangyexinwen/2530.html
- CSDN 2024 `360FsFlt`/`360Hvm64` research lead:
  https://blog.csdn.net/2401_83799022/article/details/137875851
- CSDN/OSChina mirror of achillis `360FsFlt` Win64 self-protection analysis:
  https://blog.csdn.net/weixin_34032779/article/details/92695834

**Inventory / metadata**

- FreeFixer `ZhuDongFangYu.exe` metadata:
  https://www.freefixer.com/library/file/ZhuDongFangYu.exe-41973/
- file.net `360Tray.exe` path notes:
  https://www.file.net/process/360tray.exe.html
- BleepingComputer FRST driver inventory sample:
  https://www.bleepingcomputer.com/forums/t/594401/360-total-security-may-have-hosed-my-computer/
  https://www.bleepingcomputer.com/forums/t/588455/computer-keeps-changing-proxy-settings-on-its-own/
- Dr.Web 2015 historical 360 component inventory:
  https://vms.drweb-av.de/virus/?i=10760468

**Threat intelligence process inventories**

- Antiy PowerShell malware report:
  https://www.antiy.com/response/MSShell/Analysis_of_several_events_that_use_PowerShell_to_transmit_malware.pdf
- Operation Dragon Castling process list:
  https://malware.news/t/operation-dragon-castling-apt-group-targeting-betting-companies/58566
- Elastic RONINGLOADER:
  https://www.elastic.co/security-labs/roningloader
- CN-SEC analysis referencing 360 process checks:
  https://cn-sec.com/archives/2519389.html

**Windows internals**

- Microsoft protected antimalware services:
  https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-
- Microsoft ELAM:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/install/early-launch-antimalware

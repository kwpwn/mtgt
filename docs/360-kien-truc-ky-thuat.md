# Mổ xẻ 360 (360杀毒 / 360安全卫士): Kiến trúc, process, driver, cơ chế phòng thủ & internals

> Bài viết chia sẻ kiến thức kỹ thuật về cách một bộ AV/HIPS thương mại của Trung Quốc được thiết kế từ tầng ứng dụng xuống tầng kernel. Mục đích là **hiểu nguyên lý**, không phải hướng dẫn vô hiệu hóa sản phẩm.
>
> **Về độ tin cậy nguồn** — thông tin trong bài chia làm 3 nhóm và được ghi rõ tại chỗ:
> 1. **Có nguồn công khai cụ thể**: tài liệu reverse-engineering trên 看雪/pediy, CSDN, 51CTO, Baidu Baike, blog chính thức 360, VirusTotal Blog, log gỡ phần mềm BleepingComputer, hội thảo CYBERSEC.
> 2. **Kiến thức Windows kernel internals chung** (không phải tài liệu riêng của 360) — được dán nhãn rõ.
> 3. **Proprietary / không xác định** — nói thẳng là không có thay vì suy đoán.
>
> *Phạm vi phiên bản: phần lớn RE từ các đời 6.x (x86, ~2009–2012) đến ~2021–2024. Tên file/driver và cơ chế có thể đã đổi ở bản mới nhất — hãy verify trên máy thật (xem mục 11).*

---

## 0. Tham chiếu nhanh (cheat sheet)

| Hạng mục | Thành phần chính |
|---|---|
| **Process lõi (TQ)** | `360safe.exe`, `360sd.exe`, `360tray.exe`, `ZhuDongFangYu.exe` (chủ động phòng thủ) |
| **Process lõi (quốc tế)** | `QHSafeMain.exe`, `QHSafeTray.exe`, `QHActiveDefense.exe`, `QHWatchdog.exe` |
| **Driver hiện đại** | `360AvFlt` (quét file), `360FsFlt` (self-protect + whitelist), `360Box64` (sandbox), `360elam64` (ELAM), `360Hvm64` (hypervisor 晶核), `360AntiHacker`/`360netmon` (mạng), `BAPIDRV64` (cầu nối kernel) |
| **Driver đời cũ** | `HookPort.sys` + `360SelfProtection.sys` (hook KiFastCallEntry) |
| **Engine** | 360 Cloud (云查) · QVM/QVM II (AI) · BitDefender · Avira (bản TQ) · QEX (script) · KunPeng (sửa hệ thống) |
| **Self-protection** | ObRegisterCallbacks (process) + minifilter (file) + whitelist PID + watchdog + ELAM (boot) + hypervisor (memory) |
| **PPL?** | Có khả năng kỹ thuật nếu dịch vụ antimalware đăng ký qua ELAM, nhưng **chưa có nguồn công khai xác nhận** `360safe.exe`/`360sd.exe`/`ZhuDongFangYu.exe` chạy PPL trên bản nội địa; phải verify bằng `EPROCESS.Protection`, Process Explorer hoặc `GetProcessInformation(ProcessProtectionLevelInfo)` |

---

## 1. Trước hết: "360SD" là cái nào?

Hệ sinh thái 360 hay gây nhầm lẫn vì nhiều sản phẩm chồng lớp:

- **360杀毒 (360 Sha Du — "diệt virus")**: thường viết tắt **360SD**. Đây là lõi *antivirus engine*, file chính `360sd.exe`. "SD" = ShaDu = 杀毒.
- **360安全卫士 (360 Safe Guard)**: bộ *security suite* lớn hơn — chống virus + tối ưu hệ thống + vá lỗ hổng + quản lý phần mềm + tường lửa. File chính `360safe.exe`.
- **360 Total Security**: bản quốc tế, gộp gần hết tính năng vào một GUI, tiền tố process `QH...`.

Resource riêng cho bản nội địa **360安全卫士 / 360 Safeguard** nằm ở:
`docs/360-safeguard-noi-dia-kien-truc.md`. File đó tách rõ phần suite nội địa (`360Safe.exe`, `ZhuDongFangYu.exe`, 文档卫士, 主防7.0, 360Hvm64/晶核) khỏi phần 360SD thuần.

Resource riêng cho **360杀毒 / 360SD** nằm ở:
`docs/360sd-noi-dia-kien-truc.md`. File đó tập trung vào `360sd.exe`, `360rp.exe`, `360rps.exe`, quyền chạy cần verify, realtime protection, cloud scan, proactive defense và self-protection bảo vệ process/file/registry/driver.

Kết quả reverse local driver corpus bằng IDA nằm ở:
`docs/360-driver-ida-reverse-notes.md`. File đó map từng driver 360 theo binary surface: minifilter, WFP, ELAM, HVM, sensor và component cross-reference.

Khác biệt quan trọng giữa bản tiếng Trung và quốc tế: **bản tiếng Trung bật thêm engine Avira** và HIPS gắt hơn. Đây cũng là lý do các tổ chức test (AV-Comparatives, AV-TEST, Virus Bulletin) từng rút chứng nhận của 360 năm 2015 — bản gửi đi test dùng full engine BitDefender, còn bản người dùng cuối chủ yếu dùng QVM, cho kết quả thấp hơn và nhiều false positive hơn.
*(Nguồn: Wikipedia — 360 Total Security / Qihoo 360.)*

### Phân tách nhanh: 360safe vs 360sd nội địa

Hai bản nội địa hay cùng tồn tại trên máy Trung Quốc, nhưng vai trò khác nhau:

| Sản phẩm | Tên tiếng Trung | Process chính nên săn | Vai trò thực tế | Quyền chạy thường gặp | PPL? | Driver liên quan nhiều nhất |
|---|---|---|---|---|---|---|
| **360 Safe Guard** | `360安全卫士` | `360safe.exe`, `360tray.exe`, `ZhuDongFangYu.exe` | Suite/HIPS: GUI chính, tray, chủ động phòng thủ, sửa hệ thống, vá lỗi, software manager | User-mode service/tray chạy dưới tài khoản người dùng hoặc service context; enforcement mạnh nằm ở driver kernel, không nằm ở token user-mode | **Chưa xác nhận công khai**. Không nên gán nhãn PPL nếu chưa đo trực tiếp | `360FsFlt.sys` self-protect/file filter, `BAPIDRV64.sys`, `360AntiHacker64.sys`, `360netmon.sys`, `360Hvm64.sys`, `360elam64.sys` |
| **360 Antivirus** | `360杀毒`, viết tắt **360SD** | `360sd.exe`, `360rp.exe`/`360rps.exe`, có thể dùng chung `360tray.exe` | Lõi antivirus: quét file, realtime protection, engine cloud/QVM/signature | GUI/user component bình thường; quét realtime dựa vào service + minifilter | **Chưa xác nhận công khai**. Nếu có PPL thì phải là service antimalware được đăng ký qua ELAM, không suy ra từ tên `360sd.exe` | `360AvFlt.sys` realtime AV minifilter, `360FsFlt.sys`, `360Box64.sys`, `360elam64.sys` |

Kết luận ngắn: `360safe.exe` là mặt điều phối/suite của **360安全卫士**; `360sd.exe` là mặt AV của **360杀毒**. Tiến trình đáng chú ý nhất về self-protection nội địa thường không phải hai GUI này mà là `ZhuDongFangYu.exe` (主动防御服务模块), vì đây là module chủ động phòng thủ/HIPS. FreeFixer ghi metadata mẫu cũ của `ZhuDongFangYu.exe` là sản phẩm `360安全卫士`, mô tả file `360主动防御服务模块`, thường nằm trong `C:\Program Files\360\360safe\deepscan\`.

---

## 2. Triết lý kiến trúc: "Cloud – Pipe – Point" (云-管-端)

360 không theo lối AV truyền thống (một engine + một bộ signature local). Nó theo mô hình **đa engine + cloud làm não bộ**.
*(Nguồn: blog chính thức 360 — "AI in Cyber Security: How 360's QVM Works".)*

- **云 (Cloud)** — bộ não, gọi là **360安全大脑 ("Security Brain")**: kho dữ liệu khổng lồ kết hợp AI. 360 quảng bá hàng chục tỷ mẫu mã độc và hàng nghìn tỷ log.
- **管 (Pipe)** — đường truyền Internet nối client với cloud.
- **端 (Point)** — agent trên máy người dùng, thu telemetry và thực thi quyết định từ cloud.

Hệ quả thiết kế: phần cài trên máy được giữ "nhẹ" *có chủ đích*, đẩy phần nặng (reputation, phân tích mẫu mới) lên cloud → cực kỳ quan trọng cho câu hỏi "chặn mạng" (mục 7).

### Các engine chạy song song

| Engine | Bản chất | Vai trò |
|---|---|---|
| **360 Cloud (云查)** | Tra hash/checksum lên cloud | Tuyến đầu, cực nhanh. File lạ → gửi hash hỏi cloud "đã biết tốt/xấu chưa?" |
| **QVM / QVM II** | AI/ML (gốc *Qihoo Support Vector Machine*, 2010) | Bắt mã độc *chưa từng thấy* dựa trên đặc trưng học từ blacklist/whitelist. 360 nêu ~74.9% mẫu mới (số do 360 cung cấp qua VirusTotal Blog, không phải kiểm định độc lập) |
| **BitDefender** | Signature local (cấp phép) | Quét chữ ký truyền thống, chính xác cao |
| **Avira** | Signature local (cấp phép) | Bật mặc định ở **bản tiếng Trung** |
| **QEX** | Engine script/macro | Bắt script độc, macro tài liệu, exploit |
| **KunPeng (鲲鹏)** | Engine sửa hệ thống | Khôi phục thiết lập/file bị malware sửa |

Thứ tự thực thi thực tế (theo quan sát cộng đồng phân tích trên MalwareTips): **Cloud + QVM chạy trước** để lọc nhanh; nghi ngờ mới "thả" BitDefender/Avira quét sâu → giảm tải CPU nhưng tăng phụ thuộc cloud.

---

## 3. Các process chính

### Bản tiếng Trung (360安全卫士 / 360杀毒)
*(Nguồn: file.net, Baidu Baike, tài liệu kỹ thuật tiếng Trung.)*

| Process | Tên gọi | Chức năng |
|---|---|---|
| `360safe.exe` | 主程序 | Tiến trình chính Safe Guard, GUI + điều phối |
| `360sd.exe` | 360杀毒 | Lõi antivirus, GUI quét |
| `360tray.exe` | 托盘 + 实时保护 | Icon khay + realtime protection (thư mục `safemon`) |
| `ZhuDongFangYu.exe` | 主动防御服务 | **Trái tim HIPS** — chủ động phòng thủ. Trước tên `krnl360svc`, đổi sang pinyin cho dễ nhận diện. Realtime protection, file audit, "smart acceleration" |
| `360rp.exe`/`360rps.exe` | 实时保护 | Realtime protection của module diệt virus |
| `LiveUpdate360.exe` | 升级 | Cập nhật signature + cloud config |
| `360leakfixer.exe` | 漏洞修复 | Quét & vá lỗ hổng Windows |
| `softmgr.exe` | 软件管家 | Quản lý phần mềm |

`ZhuDongFangYu.exe` nổi tiếng **không kill được từ Task Manager** ("无法访问" / access denied). Muốn tắt phải vào trong sản phẩm: *木马防火墙 → 设置 → 自我保护 → 临时关闭*.

### Quyền chạy và PPL của bản nội địa

Không nên kết luận "`360safe.exe`/`360sd.exe` là PPL" chỉ vì chúng khó kill. Trên Windows, PPL/Protected Service cho antimalware là cơ chế riêng: vendor cần ELAM driver và phải đăng ký service với `SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT`; sau đó Windows Code Integrity mới bảo vệ service khỏi injection/write từ tiến trình không được bảo vệ. Microsoft mô tả rõ yêu cầu này trong tài liệu *Protecting anti-malware services* và *Early Launch AntiMalware*.

Với 360, nguồn công khai cho thấy:

- `360elam64.sys` tồn tại trên nhiều máy thật, nên 360 **có thành phần ELAM**.
- Không có nguồn công khai đủ chắc nói `360safe.exe`, `360sd.exe`, `360tray.exe` hoặc `ZhuDongFangYu.exe` của bản nội địa đang chạy ở `Antimalware-Light/PPL`.
- Hành vi "access denied khi kill" có thể đến từ `ObRegisterCallbacks`/driver self-protection (`360FsFlt`) tước quyền handle terminate/write, không nhất thiết là PPL.
- Báo cáo Elastic RONINGLOADER 2025 nhắc PPL abuse để đụng Defender, nhưng với Qihoo 360 thì malware lại dùng driver riêng để kill `360Safe.exe`, `360Tray.exe`, `ZhuDongFangYu.exe`. Điều này là bằng chứng thực tế rằng các process này là target self-protection/AV, nhưng **không chứng minh chúng là PPL**.

Checklist lab để chốt PPL:

| Câu hỏi | Cách kiểm |
|---|---|
| Process có PPL không? | Kernel debugger: `dt -r1 nt!_EPROCESS <addr>` xem `_PS_PROTECTION`; hoặc Process Explorer/Process Hacker xem cột protection nếu build hỗ trợ |
| Service có launch-protected không? | `sc qprotection <service>` trên Windows hỗ trợ; hoặc SCM API `QueryServiceConfig2(SERVICE_CONFIG_LAUNCH_PROTECTED)` |
| Nếu PPL là antimalware-light? | `EPROCESS.Protection.Level` thường là `0x31` cho `AntimalwareLight` theo ví dụ Microsoft |
| Nếu không PPL nhưng vẫn kill fail? | Kiểm tra handle desired access bị strip bởi `ObRegisterCallbacks`; so với trạng thái driver `360FsFlt` đang load |

### Bản quốc tế (360 Total Security)
*(Nguồn: file.net, MalwareTips.)*

| Process | Vai trò |
|---|---|
| `QHSafeMain.exe` | GUI chính |
| `QHSafeTray.exe` | Khay hệ thống (≈ `360tray.exe`) |
| `QHActiveDefense.exe` | Chủ động phòng thủ (≈ `ZhuDongFangYu.exe`) |
| `QHWatchdog.exe` | **Watchdog** — giám sát & khởi động lại tiến trình bị giết |
| `QHSafeScanner.exe` | Engine quét |

---

## 4. Các driver kernel (.sys) hiện đại và chức năng
*(Nguồn: log gỡ phần mềm BleepingComputer 2015–2025, mô tả driver trong log Netch, System Explorer.)*

Đây là xương sống thật sự — quyền lực của 360 nằm ở ring 0. Đường dẫn điển hình `C:\Windows\System32\Drivers\`:

| Driver | Loại | Chức năng |
|---|---|---|
| `360AvFlt.sys` | **Minifilter** | Quét file thời gian thực; hook I/O hệ thống file để chặn/quét file khi tạo/mở/ghi/thực thi |
| `360FsFlt.sys` | **Minifilter** | Filter hệ thống file lõi của chủ động phòng thủ + **tự bảo vệ**; chứa **whitelist** .exe trong thư mục cài 360 (ghi nhớ PID) |
| `360Box64.sys` | **Minifilter** | **Sandbox**; tạo thư mục ảo `C:\360SANDBOX` chạy file nghi ngờ cách ly |
| `360AntiHacker64.sys` | Network/kernel | "网络防黑模块" — chống tấn công mạng ở tầng kernel |
| `360netmon.sys` | Network monitor | Giám sát kết nối mạng, gắn tường lửa |
| `360Camera64.sys` | Device | Bảo vệ webcam (防偷拍), chống truy cập camera trái phép |
| `360elam64.sys` | **ELAM** | *Early Launch Anti-Malware* — nạp rất sớm khi boot, trước driver bên thứ ba, phân loại boot driver an toàn/độc |
| `360Hvm64.sys` | **Hypervisor** | Bảo vệ dựa trên ảo hóa CPU (VT-x/EPT); nội bộ gọi là **"晶核" (jīng hé / crystal core)**; bảo vệ vùng nhớ & cấu trúc nhân **kể cả khỏi mã chạy trong kernel** |
| `BAPIDRV64.sys` | Kernel API helper | Cung cấp thao tác kernel cấp thấp cho tiến trình user-mode — cầu nối user↔kernel |

360 dùng **đồng thời ELAM (boot sớm) + minifilter (file) + hypervisor (memory) + Object callbacks (process)** — phủ gần như mọi tầng một AV nghiêm túc cần kiểm soát.

---

## 5. Nó detect như thế nào? (luồng end-to-end)

Khi file xuất hiện hoặc tiến trình hành động:

1. **Chặn ở I/O (kernel)** — `360AvFlt.sys`/`360FsFlt.sys` bắt sự kiện file/process tại minifilter callback, *trước khi* file kịp chạy.
2. **Tra cloud (云查)** — tính hash, hỏi Security Brain. Cloud trả lời rõ → quyết định ngay. Tuyến nhanh & mạnh nhất.
3. **QVM (AI)** — file lạ → engine ML chấm điểm theo đặc trưng học được. "Hit" → cách ly. Tuyến bắt zero-day.
4. **Signature local (BitDefender/Avira)** — quét chữ ký mẫu đã biết, chạy cả khi offline.
5. **QEX** — soi riêng script/macro/exploit.
6. **HIPS hành vi (主动防御)** — tuyến cuối: mã độc dù né detect tĩnh *vẫn phải hành động* (sửa registry khởi động, ghi thư mục hệ thống, inject...). HIPS giám sát các hành vi này, **gửi thông tin tiến trình lên cloud để phân tích thêm** *(Nguồn: tài liệu 360 trích trên MalwareTips về HIPS proactive defense.)*

---

## 6. Internals: tiến hóa của self-protection qua 3 thời kỳ

Phần sâu nhất. Kiến trúc 360 thay đổi theo từng đời Windows — hiểu mạch tiến hóa này quan trọng hơn nhớ tên file.

### Thời kỳ 1 — `HookPort.sys` + hook `KiFastCallEntry` (x86, ~2009–2012)
*Nguồn: achillis (看雪/pediy thread 99460, 2009), sudami (邪恶八进制 eviloctal), lionzl & qq1841370452 (CSDN), `hookport.sys` (Baidu Baike).*

Đời 360 v6 (`6.0.1.1003`, `HookPort.sys` v1.0.0.1005):

- **Không** sửa trực tiếp SSDT/ShadowSSDT mà hook hàm **không export** `KiFastCallEntry` — điểm mọi system call đều đi qua sau khi vào kernel. Vì đa số công cụ ARK chỉ kiểm tra hai bảng SSDT nên không phát hiện được hook → cực kỳ ẩn.
- Lấy địa chỉ `KiFastCallEntry` (không export) bằng mẹo: hook `ZwSetEvent` với hàm proxy `_HookKiFastCallEntryKnrl` trong hookport.
- Kiến trúc tách lớp sạch: `HookPort.sys` = khung lọc + hàm stub (không chứa policy); **policy nằm ở `360SelfProtection.sys`**, giao tiếp qua *device extension*. Dữ liệu: `SERVICE_FILTER_INFO_TABLE` (địa chỉ gốc + hook) và `FILTERFUN_RULE_TABLE` (luật lọc).
- Là driver **BOOT_START** (nạp sớm qua `HKLM\SYSTEM\...\Services\HookPort`), hook ~0x57 hàm dịch vụ; struct quản lý hook chiếm ~6KB liên tục — "đổi không gian lấy thời gian" vì KiFastCallEntry là hot path. *(Nguồn vênh nhau: Baidu nói ~0x57; bản kê achillis liệt kê tới 0x4B. Giữ cả hai để đối chiếu.)*
- Bảo vệ cửa sổ GUI: hook ShadowSSDT các hàm `NtUserFindWindowEx`, `NtUserQueryWindow`, `NtUserBuildHwndList`... phục vụ bảo vệ cửa sổ, nhập liệu an toàn, chống chụp màn hình.

### Thời kỳ 2 — `ObRegisterCallbacks` + `360FsFlt.sys` (x64 / kỷ nguyên PatchGuard, ~2011+)
*Nguồn: "浅析360在系统的进程自保护及突破" — achillis (CSDN/51CTO, 2011).*

Lên x64, hook KiFastCallEntry/SSDT chết vì **PatchGuard**. Lý luận của tác giả (thuyết phục): 360 là phần mềm thương mại nên sẽ **không** vô hiệu PatchGuard để inline-hook kernel — vừa kém ổn định, vừa cho đối thủ cớ "phá cơ chế bảo mật hệ thống". Nên dùng đúng cách Microsoft khuyến nghị: `ObRegisterCallbacks`.

- Trên Win64 đời đó 360 chỉ nạp **hai driver**: `360FsFlt.sys` + một driver mạng.
- `360FsFlt.sys` đăng ký `ObRegisterCallbacks` giám sát mọi handle tiến trình/luồng; phát hiện handle "có hại cho chính nó" → đóng handle & trả về lỗi. **Đây chính là lý do** Task Manager báo access-denied khi cố kill `ZhuDongFangYu.exe`: không phải process "bất tử" mà là handle bị tước quyền terminate/write.
- Bypass thời đó (mức khái niệm): gửi message qua *window handle* — tấn công GUI qua đường windowing thay vì mở handle tiến trình.

### Thời kỳ 3 — minifilter whitelist + hypervisor `360Hvm64` "晶核" (~2021–2024)
*Nguồn: "杀死那个名为360安全的软件" (CSDN, 2024), tham chiếu thread 281120 (看雪) & bài procexp-driver 2021 của xjun.*

Tầng hiện đại, "internals" sâu nhất công khai có:

- Trong callback của `360FsFlt` có **whitelist** = các .exe trong thư mục cài 360; mỗi lần chạy ghi lại **PID**. Chỉ PID trong whitelist được thao tác lên đối tượng được bảo vệ.
- Lớp chống lạm dụng whitelist: dù khởi động exe của 360 để lọt whitelist, exe đó vẫn **không thể bị inject/ghi** — API đã bị can thiệp. Handle có quyền cao nhất nhưng "không có không gian thao tác".
- Lớp can thiệp nằm ở hypervisor: trong `360Hvm64` ("晶核"/crystal core) có **bảng kiểm tra lời gọi `NtWriteVirtualMemory`**. Tức 360 dùng ảo hóa CPU (kiểu EPT/VMEXIT) **thẩm tra thao tác ghi bộ nhớ ở tầng dưới cả kernel** — khác biệt lớn so với thời kỳ 2.
- Điểm yếu đã công bố (mức ý tưởng, **không** phải tutorial): nghiên cứu dùng driver `procexp` phá PPL → inject `csrss` → qua `csrss` kết thúc phần mềm bảo vệ; phân tích `360FsFlt`+`360Hvm64` tìm ra khiếm khuyết cho phép kết thúc `ZhuDongFangYu.exe`/`360tray.exe`.

---

## 7. Chặn ra mạng có làm nó "mất 95% sức mạnh" không?

**Định hướng đúng, nhưng 95% là cường điệu.**

**Cái sẽ mất khi offline:**
- **Engine Cloud (云查)** — tuyến nhanh & quan trọng nhất, gần như tê liệt.
- **Khả năng bắt mẫu *mới*** — có quan sát thực nghiệm (MalwareTips): ngắt mạng thì tỉ lệ phát hiện **giảm rất mạnh**, engine cloud được xem là engine mạnh nhất của 360.
- **Phân tích hành vi nâng cao** — HIPS gửi tiến trình đáng ngờ lên cloud "phán xử"; mất kết nối chỉ còn luật cục bộ.
- **Cập nhật signature** — đứng yên, phủ sóng tụt theo thời gian.

**Cái *vẫn còn* khi offline (nên không phải 95%):**
- Engine signature local **BitDefender + Avira** (bản TQ) vẫn quét mọi mẫu đã có chữ ký.
- **Model QVM local** vẫn chấm điểm heuristic ở mức nhất định.
- **HIPS hành vi cục bộ** + **minifilter realtime** + **self-protection** vẫn chặn nhiều hành vi nguy hiểm.

**Kết luận:** Cloud là layer mạnh nhất và là điểm khác biệt của 360 → cắt mạng làm nó yếu đi đáng kể, đặc biệt với mã độc *mới/đa hình*. Nhưng **không sụp về 0**. Con số thật phụ thuộc loại mẫu: mẫu cũ có signature → offline gần như không ảnh hưởng; mẫu mới/đa hình → mức suy giảm mới tiến gần cảm nhận "mất gần hết".

---

## 8. Tổng hợp cơ chế tự bảo vệ (theo tầng)

| Tầng | Cơ chế | Driver/thành phần |
|---|---|---|
| **Process** | `ObRegisterCallbacks` tước quyền handle terminate/write | `360FsFlt` |
| **File/Registry/Service** | Minifilter chặn xóa/sửa + whitelist PID | `360FsFlt` |
| **Memory** | Hypervisor thẩm tra `NtWriteVirtualMemory` (EPT) | `360Hvm64` (晶核) |
| **Boot** | ELAM nạp sớm, bảo vệ chuỗi khởi động | `360elam64` |
| **Process sống lại** | Watchdog / canh gác chéo | `QHWatchdog` (quốc tế) |
| **Đời cũ (x86)** | Hook `KiFastCallEntry`, lọc syscall | `HookPort` + `360SelfProtection` |

Chỉ tắt được self-protection **từ bên trong sản phẩm** (*设置 → 自我保护 → 临时关闭*).

---

## 9. Điểm yếu đã được công bố (góc nghiên cứu)

Để bài cân bằng — đã công khai qua CVE/hội thảo, ở mức khái niệm:

- **BYOVD (Bring Your Own Vulnerable Driver)**: tại **CYBERSEC 2023** (Đài Loan) có demo tấn công 360 Total Security 6.6.0.1060 bằng cách lạm dụng driver đã ký nhưng có lỗ hổng (vd `RTCore64.sys` của MSI, **CVE-2019-16098**) để vô hiệu DSE, nạp driver chưa ký, rồi **"null out" các `ObRegisterCallbacks`** của 360 — khi callback bảo vệ bị xóa, tiến trình 360 có thể bị thao túng/kết thúc. *(Nguồn: GitHub zeze-zeze/CYBERSEC2023-BYOVD-Demo.)* Đây là điểm yếu **chung của mọi AV dựa vào ObCallbacks**, không riêng 360.
- **Phân tích `360FsFlt`+`360Hvm64`** (CSDN 2024): khiếm khuyết logic trong whitelist/bảo vệ, về lý thuyết cho phép kết thúc tiến trình được bảo vệ nếu chiếm được quyền sửa nhớ phù hợp.

**Bài học thiết kế:** self-protection nhiều lớp đến đâu cũng **không chống được kẻ tấn công đã có code chạy ở kernel** (qua BYOVD). Đây là giới hạn cố hữu của mô hình "AV tự bảo vệ mình từ trong cùng một OS".

---

## 10. Những thứ KHÔNG có nguồn chắc (nói thẳng)

- **Altitude minifilter** của `360AvFlt`/`360FsFlt`/`360Box64`: không có con số từ nguồn nào. *Windows chung*: altitude ở `HKLM\SYSTEM\CurrentControlSet\Services\<tên>\Instances`; minifilter AV thường ở dải `320000–329999` ("FSFilter Anti-Virus"). Altitude *chính xác* của 360 phải tự xem bằng `fltmc instances`.
- **Protocol cloud** (endpoint, format gói, mã hóa): proprietary, không có tài liệu công khai đáng tin.
- **IOCTL / device name của `BAPIDRV64`**: vai trò "cầu nối user↔kernel" là suy ra từ tên + bối cảnh; IOCTL cụ thể không có nguồn.
- **Feature vector của QVM**: proprietary, chưa từng công bố chi tiết.
- **PPL của process nội địa**: 360 có `360elam64.sys`, nên về mặt Windows có thể đăng ký antimalware protected service. Nhưng chưa có nguồn công khai xác nhận process nào của 360 nội địa đang chạy `AntimalwareLight`; phải đo trực tiếp trên máy cài đúng phiên bản.

---

## 11. Tự kiểm chứng trên máy thật

Vì internals thay đổi theo phiên bản, đừng tin bài này mù quáng — kiểm tra trực tiếp:

| Mục tiêu | Lệnh/công cụ |
|---|---|
| Liệt kê minifilter + altitude | `fltmc instances` / `fltmc filters` |
| Liệt kê driver đang nạp | `driverquery /v` |
| Xem process + handle + DLL | Process Explorer (Sysinternals) |
| Xem object/callback/device | WinObj (Sysinternals) |
| Xem service & start type | `sc query`, `sc qc <tên>` |
| Xem service launch-protected/PPL | `sc qprotection <service>` nếu Windows build hỗ trợ; hoặc kernel debugger xem `_EPROCESS.Protection` |
| Xem registry driver | `HKLM\SYSTEM\CurrentControlSet\Services\<tên>` |

---

## 12. Nguồn tham khảo (theo nhóm)

**Chính thức / vendor**
- Blog 360 Total Security — "AI in Cyber Security: How 360's QVM Works" (cloud-pipe-point, QVM 2010).
- VirusTotal Blog (2014) — mô tả QVM + số ~74.9% (do 360 cung cấp).
- Microsoft Learn — *Protecting anti-malware services*:
  https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-
- Microsoft Learn — *Overview of Early Launch AntiMalware*:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/install/early-launch-antimalware

**Bách khoa / báo chí**
- Wikipedia — *360 Total Security*, *Qihoo 360*, *Multiscanning* (engine, tranh cãi 2015).
- Wikipedia zh — *360安全卫士*:
  https://zh.wikipedia.org/wiki/360%E5%AE%89%E5%85%A8%E5%8D%AB%E5%A3%AB
- Wikipedia zh — *360杀毒*:
  https://zh.wikipedia.org/wiki/360%E6%9D%80%E6%AF%92
- Baidu Baike — `hookport.sys`, `zhudongfangyu.exe`.
- file.net / file.info — `360tray.exe`, `QHSafeTray.exe`.
- FreeFixer — `ZhuDongFangYu.exe` file metadata:
  https://www.freefixer.com/library/file/ZhuDongFangYu.exe-41973/

**Reverse-engineering (kernel internals)**
- achillis — phân tích HOOK 360 (看雪/pediy thread 99460, 2009; CSDN/cnblogs); "浅析360在系统的进程自保护及突破" (2011).
- sudami (邪恶八进制 eviloctal) — phân tích KiFastCallEntry hook.
- lionzl, qq1841370452, jgftyfc (CSDN) — `hookport.sys`, `360SelfProtection.sys`.
- "杀死那个名为360安全的软件" / "杀死名为360安全的软件" (CSDN, 2024) — `360FsFlt` whitelist, `360Hvm64` 晶核; tham chiếu 看雪 thread 281120 & xjun (procexp, 2021).

**Forensics / gỡ phần mềm**
- BleepingComputer (2015–2025) — danh sách driver `.sys` thực tế qua FRST log.
- BleepingComputer sample FRST log with `360AvFlt`, `360Box64`, `360Camera`, `360FsFlt`, `BAPIDRV64`:
  https://www.bleepingcomputer.com/forums/t/594401/360-total-security-may-have-hosed-my-computer/
- BleepingComputer sample FRST log with `360FsFlt` and `BAPIDRV64`:
  https://www.bleepingcomputer.com/forums/t/588455/computer-keeps-changing-proxy-settings-on-its-own/
- GitHub netchx/netch issue #965 — mô tả driver 360.

**Hội thảo / CVE**
- CYBERSEC 2023 BYOVD Demo (GitHub zeze-zeze) — BYOVD null `ObRegisterCallbacks`; CVE-2019-16098 (`RTCore64.sys`).
- Elastic Security Labs — RONINGLOADER/DragonBreath 2025, nhắc target process `360Safe.exe`, `360Tray.exe`, `ZhuDongFangYu.exe` và PPL abuse ở nhánh Defender:
  https://www.elastic.co/security-labs/roningloader

*Lưu ý: tên file/driver có thể thay đổi giữa các phiên bản. Bài phản ánh các bản phổ biến ~2009–2025.*

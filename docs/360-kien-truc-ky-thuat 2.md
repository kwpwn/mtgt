# Mổ xẻ 360 (360杀毒 / 360安全卫士): Kiến trúc, process, driver, cơ chế phòng thủ & internals

> Bài viết chia sẻ kiến thức kỹ thuật về cách một bộ AV/HIPS thương mại của Trung Quốc được thiết kế từ tầng ứng dụng xuống tầng kernel. Mục đích là **hiểu nguyên lý**, không phải hướng dẫn vô hiệu hóa sản phẩm.
>
> **Về độ tin cậy nguồn** — thông tin trong bài chia làm 3 nhóm và được ghi rõ tại chỗ:
> 1. **Có nguồn công khai cụ thể**: tài liệu reverse-engineering trên 看雪/pediy, CSDN, 51CTO, Baidu Baike, blog chính thức 360, VirusTotal Blog, log gỡ phần mềm BleepingComputer, hội thảo CYBERSEC.
> 2. **Kiến thức Windows kernel internals chung** (không phải tài liệu riêng của 360) — được dán nhãn rõ.
> 3. **Proprietary / không xác định** — nói thẳng là không có thay vì suy đoán.
>
> **Mỗi claim trong bài có một trong các nhãn độ tin cậy sau** (xem cột "Cách verify" trong các bảng và mục 13):
> - 🟢 **[Tự kiểm chứng được]** — bạn có thể tự xác nhận trên máy bằng công cụ phổ thông (Process Explorer, `fltmc`, `driverquery`, WinObj). Không cần tin ai.
> - 🟡 **[RE công khai]** — đến từ phân tích dịch ngược của bên thứ ba; có thể đọc lại bài gốc, nhưng để tự xác minh tận gốc thì cần kỹ năng IDA/WinDbg.
> - 🔵 **[Vendor công bố]** — do chính 360 nói; có lợi ích thương mại nên đọc với thái độ dè dặt.
> - 🔴 **[Suy luận / không nguồn cứng]** — suy ra từ tên file + bối cảnh, hoặc kiến thức Windows chung. Không có tài liệu xác nhận riêng cho 360.
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

---

## 1. Trước hết: "360SD" là cái nào?

Hệ sinh thái 360 hay gây nhầm lẫn vì nhiều sản phẩm chồng lớp:

- **360杀毒 (360 Sha Du — "diệt virus")**: thường viết tắt **360SD**. Đây là lõi *antivirus engine*, file chính `360sd.exe`. "SD" = ShaDu = 杀毒.
- **360安全卫士 (360 Safe Guard)**: bộ *security suite* lớn hơn — chống virus + tối ưu hệ thống + vá lỗ hổng + quản lý phần mềm + tường lửa. File chính `360safe.exe`.
- **360 Total Security**: bản quốc tế, gộp gần hết tính năng vào một GUI, tiền tố process `QH...`.

Khác biệt quan trọng giữa bản tiếng Trung và quốc tế: **bản tiếng Trung bật thêm engine Avira** và HIPS gắt hơn. Đây cũng là lý do các tổ chức test (AV-Comparatives, AV-TEST, Virus Bulletin) từng rút chứng nhận của 360 năm 2015 — bản gửi đi test dùng full engine BitDefender, còn bản người dùng cuối chủ yếu dùng QVM, cho kết quả thấp hơn và nhiều false positive hơn.
*(Nguồn: Wikipedia — 360 Total Security / Qihoo 360.)*

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
| **QVM / QVM II** | AI/ML (gốc *Qihoo Support Vector Machine*, 2010) | Bắt mã độc *chưa từng thấy* dựa trên đặc trưng học từ blacklist/whitelist. 360 nêu ~74.9% mẫu mới (số do 360 cung cấp qua VirusTotal Blog, không phải kiểm định độc lập) 🔵. *Internals đã biết:* tên gợi ý lõi ban đầu là SVM (máy vector hỗ trợ) huấn luyện trên đặc trưng file PE; **feature vector cụ thể thì proprietary, chưa từng công bố** (xem mục 10) 🔴 |
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

> **Cách tự verify bảng này** 🟢: mở **Process Explorer** (Sysinternals) → các process trên hiện ngay với cột *Company Name* = "360" / "Qihoo". Cột *Path* cho thấy thư mục cài. Chuột phải → *Properties → Strings/Image* xem mô tả. Để thấy vì sao không kill được: Process Explorer → chọn `ZhuDongFangYu.exe` → menu *Handle* → thử *Close Handle* sẽ báo lỗi; hoặc dùng `Process Hacker` xem *Protection* và quyền trên token. Tên gọi tiếng Trung (主动防御 v.v.) là 🔵 do GUI/tài liệu 360 đặt.

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

| Driver | Loại | Chức năng | Cách verify / Độ tin cậy |
|---|---|---|---|
| `360AvFlt.sys` | **Minifilter** | Quét file thời gian thực; hook I/O hệ thống file để chặn/quét file khi tạo/mở/ghi/thực thi | 🟢 `fltmc filters` thấy tên + altitude; sự tồn tại & loại minifilter tự xác nhận được. Chi tiết "hook gì" thì 🟡 |
| `360FsFlt.sys` | **Minifilter** | Filter hệ thống file lõi của chủ động phòng thủ + **tự bảo vệ**; chứa **whitelist** .exe trong thư mục cài 360 (ghi nhớ PID) | 🟢 thấy bằng `fltmc`; 🟡 phần whitelist/PID đến từ RE (CSDN 2024) |
| `360Box64.sys` | **Minifilter** | **Sandbox**; tạo thư mục ảo `C:\360SANDBOX` chạy file nghi ngờ cách ly | 🟢 thư mục `C:\360SANDBOX` xuất hiện trên máy thật khi sandbox chạy; driver thấy bằng `fltmc` |
| `360AntiHacker64.sys` | Network/kernel | "网络防黑模块" — chống tấn công mạng ở tầng kernel | 🟢 thấy bằng `driverquery`; 🔴 chi tiết "chống gì" suy từ tên |
| `360netmon.sys` | Network monitor | Giám sát kết nối mạng, gắn tường lửa | 🟢 thấy bằng `driverquery`; 🔴 vai trò suy từ tên + bối cảnh |
| `360Camera64.sys` | Device | Bảo vệ webcam (防偷拍), chống truy cập camera trái phép | 🟢 thấy bằng `driverquery`; 🟡 chức năng khớp tính năng quảng bá trong GUI |
| `360elam64.sys` | **ELAM** | *Early Launch Anti-Malware* — nạp rất sớm khi boot, trước driver bên thứ ba, phân loại boot driver an toàn/độc | 🟢 ELAM phải đăng ký với Windows; xem `HKLM\SYSTEM\...\Services\360elam64` Type=ELAM. Cơ chế ELAM là 🟢 chuẩn Microsoft |
| `360Hvm64.sys` | **Hypervisor** | Bảo vệ dựa trên ảo hóa CPU (VT-x/EPT); nội bộ gọi là **"晶核" (jīng hé / crystal core)**; bảo vệ vùng nhớ & cấu trúc nhân **kể cả khỏi mã chạy trong kernel** | 🟢 sự tồn tại driver + tên "Hvm" thấy được; 🟡 tên nội bộ "晶核" và bảng check `NtWriteVirtualMemory` từ RE (CSDN 2024) |
| `BAPIDRV64.sys` | Kernel API helper | Cung cấp thao tác kernel cấp thấp cho tiến trình user-mode — cầu nối user↔kernel | 🟢 thấy driver + device object bằng WinObj; 🔴 vai trò "cầu nối" + IOCTL cụ thể là suy luận, không nguồn cứng |

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

> **Cơ chế EPT hoạt động thế nào (kiến thức Intel VT-x chung — không riêng 360)** 🔴 áp dụng cho 360 / 🟢 về nguyên lý: hypervisor đặt CPU vào chế độ VMX root, hệ điều hành thật chạy như "guest". Hypervisor có thể đánh dấu trang nhớ chứa cấu trúc nhạy cảm (vd vùng code của `ZhuDongFangYu.exe`, hoặc bảng dịch vụ) là **read-only ở tầng EPT** (Extended Page Table — bảng dịch địa chỉ thứ hai mà guest không sửa được). Khi có lệnh ghi vào trang đó, CPU sinh **VMEXIT** → quyền điều khiển nhảy lên hypervisor → hypervisor xét "ai ghi, ghi gì" rồi cho phép hoặc chặn. Vì kiểm tra xảy ra *dưới* kernel, ngay cả mã chạy ở ring 0 (driver độc) cũng không qua mặt được — đó là điều một AV chạy thuần ở ring 0 (thời kỳ 2) không làm nổi. Việc 360 *cụ thể* gắn check vào `NtWriteVirtualMemory` là 🟡 (từ RE CSDN 2024); còn nguyên lý EPT/VMEXIT là kiến thức kiến trúc Intel công khai, tự đọc trong *Intel SDM Vol.3C* được.
- Điểm yếu đã công bố (mức ý tưởng, **không** phải tutorial): nghiên cứu dùng driver `procexp` phá PPL → inject `csrss` → qua `csrss` kết thúc phần mềm bảo vệ; phân tích `360FsFlt`+`360Hvm64` tìm ra khiếm khuyết cho phép kết thúc `ZhuDongFangYu.exe`/`360tray.exe`.

---

## 6b. "Làm sao người ta biết được?" — phương pháp reverse-engineering

Đây là phần trả lời thẳng câu hỏi *nguồn gốc tri thức ở đâu ra*. Mọi claim ở mục 4–6 không phải do 360 công bố, mà do cộng đồng RE dựng lại bằng quy trình dưới đây. Hiểu quy trình giúp bạn **tự đánh giá** claim nào đáng tin, claim nào là suy đoán — và tự làm lại nếu muốn.

### Bước 1 — Quan sát hành vi (black-box, ai cũng làm được) 🟢
Không cần dịch ngược gì. Công cụ: **Procmon** (Sysinternals) ghi mọi thao tác file/registry/process; **Process Explorer/Hacker** xem handle, thread, DLL nạp; **fltmc** liệt kê minifilter + altitude; **WinObj** xem device object & callback; **Wireshark** bắt gói mạng. Cách "360 không cho kill process" hay "tạo `C:\360SANDBOX`" được phát hiện thuần bằng quan sát — nên chúng mang nhãn 🟢. Đây là tầng bằng chứng *mạnh nhất* vì bất kỳ ai cũng tái lập được.

### Bước 2 — Liệt kê & phân loại driver 🟢→🟡
`driverquery /v`, key registry `HKLM\SYSTEM\CurrentControlSet\Services\<tên>` (xem `Type`, `Start`, `ImagePath`, `Group`), và **log FRST của BleepingComputer** (người dùng dán log gỡ phần mềm → lộ danh sách `.sys` thật trên máy thật). Biết *driver tồn tại + loại gì* là 🟢; biết *nó hook hàm nào* thì phải sang bước 3.

### Bước 3 — Dịch ngược tĩnh (static RE) 🟡
Mở file `.sys`/`.exe` trong **IDA Pro / Ghidra**. Kỹ thuật điển hình mà các tác giả 看雪/CSDN dùng:
- **Tìm chuỗi & import**: bảng import của driver lộ nó gọi `ObRegisterCallbacks`, `FltRegisterFilter`, `PsSetCreateProcessNotifyRoutine`... → suy ra cơ chế tự bảo vệ. Đây là cách biết "thời kỳ 2 dùng ObRegisterCallbacks".
- **Đối chiếu structure**: tên struct như `SERVICE_FILTER_INFO_TABLE`, `FILTERFUN_RULE_TABLE` (mục 6 thời kỳ 1) đến từ việc tác giả đặt tên sau khi đọc layout — *không phải* tên chính thức của 360. Cần nhớ điều này khi đánh giá độ chắc.
- **Lần theo cross-reference**: từ một hàm kernel quan tâm, truy ngược xem ai gọi nó → dựng được luồng điều khiển.

### Bước 4 — Dịch ngược động (dynamic RE) 🟡
**WinDbg** kernel debugging (thường qua máy ảo + named pipe/serial vì debug kernel làm treo máy thật). Đặt breakpoint trên `KiFastCallEntry`, dump SSDT/ShadowSSDT (`dps nt!KiServiceTable`), so địa chỉ thực với gốc để **phát hiện hook** — chính là cách sudami/achillis thấy 360 hook `KiFastCallEntry` thay vì SSDT. Với hypervisor (`360Hvm64`) phải dùng kỹ thuật khó hơn (đọc cấu trúc VMCS, bẫy VMEXIT) — đây là lý do phần "晶核 kiểm tra `NtWriteVirtualMemory`" hiếm nguồn và chỉ 🟡.

### Bước 5 — Đối chiếu chéo nhiều nguồn (điều bài này cố làm)
Một bài RE đơn lẻ có thể sai/lỗi thời. Cách tăng độ tin: **so các nguồn độc lập**. Ví dụ trong bài: số hàm bị hook — Baidu nói ~0x57, bản kê của achillis liệt kê tới 0x4B → bài giữ cả hai và ghi rõ "vênh nhau" thay vì chọn bừa. Khi hai nguồn không liên quan nói cùng một điều (vd nhiều log BleepingComputer cùng liệt kê `360FsFlt`), độ tin tăng mạnh.

### Vì sao vẫn còn vùng tối 🔴
- **Hypervisor & anti-debug**: `360Hvm64` chủ động chống bị debug; debug kernel trên máy có 360 dễ bị phát hiện/treo → ít người RE được tầng này.
- **Cloud protocol mã hóa**: bắt được gói (Wireshark) nhưng nội dung mã hóa → không đọc được format. Đây là lý do mục 10 nói thẳng "không có nguồn".
- **Code thay đổi mỗi bản**: RE của bản 6.x (2009) có thể sai với bản 2024. Luôn ưu tiên bước 1–2 (tự quan sát) hơn là tin RE cũ.

**Tóm tắt thang tin cậy:** quan sát hành vi (bước 1–2) > RE có nhiều nguồn đối chiếu (bước 3–5 + chéo) > RE đơn nguồn > suy luận từ tên file. Đọc bất kỳ claim nào trong bài, hãy hỏi: *"nó dựa trên bước nào?"*

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

| Tầng | Cơ chế | Driver/thành phần | Độ tin cậy |
|---|---|---|---|
| **Process** | `ObRegisterCallbacks` tước quyền handle terminate/write | `360FsFlt` | 🟡 RE (achillis 2011) + 🟢 hành vi access-denied tự thấy |
| **File/Registry/Service** | Minifilter chặn xóa/sửa + whitelist PID | `360FsFlt` | 🟢 chặn xóa tự thử được; 🟡 whitelist/PID từ RE |
| **Memory** | Hypervisor thẩm tra `NtWriteVirtualMemory` (EPT) | `360Hvm64` (晶核) | 🟡 RE đơn nguồn (CSDN 2024) — tin cậy thấp nhất bảng |
| **Boot** | ELAM nạp sớm, bảo vệ chuỗi khởi động | `360elam64` | 🟢 Type=ELAM trong registry; cơ chế chuẩn Microsoft |
| **Process sống lại** | Watchdog / canh gác chéo | `QHWatchdog` (quốc tế) | 🟢 kill thử → process hồi sinh, tự quan sát được |
| **Đời cũ (x86)** | Hook `KiFastCallEntry`, lọc syscall | `HookPort` + `360SelfProtection` | 🟡 RE nhiều nguồn (achillis/sudami 2009) nhưng đã lỗi thời |

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
| Xem registry driver | `HKLM\SYSTEM\CurrentControlSet\Services\<tên>` |

### Đối chiếu lệnh ↔ claim (làm theo thứ tự, từ dễ đến khó)

Quy ước: mỗi dòng dưới đây nói rõ *chạy gì* → *để xác nhận claim nào trong bài*.

1. **`fltmc filters`** (cmd admin) → liệt kê mọi minifilter + **altitude** thật. Xác nhận: `360AvFlt`, `360FsFlt`, `360Box64` có tồn tại và là minifilter (mục 4); đọc được altitude thật để lấp chỗ trống ở mục 10. Nếu thấy altitude nằm dải `320000–329999` → khớp nhóm "FSFilter Anti-Virus".
2. **`driverquery /v | findstr 360`** → liệt kê driver 360 đang nạp + `Start Mode`. Xác nhận danh sách `.sys` ở mục 4 và *kiểu khởi động* (boot/system/auto).
3. **`sc qc 360elam64`** → xem `SERVICE_START_NAME`/type. Nếu hiện cờ ELAM → xác nhận claim "360elam64 là ELAM" (mục 4, 8).
4. **`reg query "HKLM\SYSTEM\CurrentControlSet\Services\HookPort"`** (nếu là máy đời cũ) → xác nhận `Start=0` (BOOT_START) như nói ở mục 6 thời kỳ 1.
5. **Process Explorer → chọn `ZhuDongFangYu.exe` → Properties** → xem có chạy như *protected process* / handle bị giới hạn không. Thử *Kill* → access denied: xác nhận claim mục 3 & 6 thời kỳ 2 (handle bị tước quyền terminate).
6. **WinObj → `\Driver` và `\Device`** → tìm device object của `BAPIDRV64` → xác nhận nó *tồn tại*. (Lưu ý: WinObj **không** cho biết IOCTL nào — đó là lý do vai trò chi tiết của `BAPIDRV64` vẫn 🔴 ở mục 10.)
7. **Tạo thư mục/chạy file test trong thư mục cài 360 rồi thử xóa** → xác nhận self-protect file (mục 8). **Cảnh báo: làm trên máy ảo/throwaway**, đừng nghịch máy chính.
8. **`fltmc instances`** so altitude giữa `360AvFlt` và các AV khác → hiểu thứ tự lọc.

### Cái KHÔNG verify được bằng công cụ phổ thông (cần IDA/WinDbg, ngoài phạm vi bài)
- Bảng check `NtWriteVirtualMemory` trong `360Hvm64` — cần đọc VMCS/bẫy VMEXIT.
- Số hàm bị hook bởi `HookPort` (0x57 hay 0x4B) — cần dump SSDT bằng WinDbg.
- Nội dung gói cloud — mã hóa, không đọc được.

Nếu một claim ở bài *không* nằm trong danh sách "verify được" ở trên, hãy mặc định coi nó là 🟡/🔴 cho tới khi tự đọc được bài RE gốc (mục 12).

---

## 12. Nguồn tham khảo (theo nhóm)

> **Cách đọc bảng nguồn:** mỗi mục ghi *nguồn đó cho biết điều gì* và *cách tìm lại nó* (vì link cụ thể dễ chết, tên + nền tảng giúp bạn search lại). Độ tin cậy của từng loại nguồn: vendor 🔵 (có lợi ích thương mại), RE đơn nguồn 🟡, RE nhiều nguồn đối chiếu 🟡→🟢, log forensic 🟢 (dữ liệu máy thật), bách khoa 🟡.

**Chính thức / vendor** 🔵 — *đáng tin về "360 nói gì", không đáng tin như đánh giá khách quan*
- Blog 360 Total Security — "AI in Cyber Security: How 360's QVM Works" (cloud-pipe-point, QVM 2010). *Tìm lại:* search tên bài + "360totalsecurity blog".
- VirusTotal Blog (2014) — mô tả QVM + số ~74.9% (do 360 cung cấp). *Tìm lại:* "VirusTotal blog Qihoo QVM 2014".

**Bách khoa / báo chí** 🟡
- Wikipedia — *360 Total Security*, *Qihoo 360*, *Multiscanning* (engine, tranh cãi 2015). *Tìm lại:* en.wikipedia.org, mục "Controversies" có nguồn AV-Comparatives.
- Baidu Baike — `hookport.sys`, `zhudongfangyu.exe`. *Tìm lại:* baike.baidu.com + tên file (tiếng Trung).
- file.net / file.info — `360tray.exe`, `QHSafeTray.exe`. *Tìm lại:* file.net + tên process (cảnh báo: site này có quảng cáo, chỉ dùng cho mô tả process cơ bản).

**Reverse-engineering (kernel internals)** 🟡 — *cốt lõi của internals; chất lượng cao nhưng có thể lỗi thời*
- achillis — phân tích HOOK 360 (看雪/pediy thread 99460, 2009; CSDN/cnblogs); "浅析360在系统的进程自保护及突破" (2011). *Tìm lại:* search tiêu đề tiếng Trung trên kanxue.com / blog.csdn.net. Đây là nguồn gốc cho thời kỳ 1 & 2.
- sudami (邪恶八进制 eviloctal) — phân tích KiFastCallEntry hook. *Tìm lại:* "sudami KiFastCallEntry 360".
- lionzl, qq1841370452, jgftyfc (CSDN) — `hookport.sys`, `360SelfProtection.sys`. *Tìm lại:* CSDN + tên tác giả.
- "杀死那个名为360安全的软件" / "杀死名为360安全的软件" (CSDN, 2024) — `360FsFlt` whitelist, `360Hvm64` 晶核; tham chiếu 看雪 thread 281120 & xjun (procexp, 2021). *Tìm lại:* search tiêu đề CSDN. **Đây là nguồn DUY NHẤT cho phần thời kỳ 3 / hypervisor → giữ thái độ dè dặt, chưa có nguồn thứ hai đối chiếu.**

**Forensics / gỡ phần mềm** 🟢 — *dữ liệu từ máy thật, độ tin cao cho "driver nào tồn tại"*
- BleepingComputer (2015–2025) — danh sách driver `.sys` thực tế qua FRST log. *Tìm lại:* bleepingcomputer.com forums "Am I infected" + "360" + ".sys"; mỗi log là một máy thật khác nhau → nhiều log = đối chiếu chéo tốt.
- GitHub netchx/netch issue #965 — mô tả driver 360. *Tìm lại:* github.com/netchx/netch/issues.

**Hội thảo / CVE** 🟢→🟡
- CYBERSEC 2023 BYOVD Demo (GitHub zeze-zeze) — BYOVD null `ObRegisterCallbacks`; CVE-2019-16098 (`RTCore64.sys`). *Tìm lại:* github.com/zeze-zeze + "CYBERSEC2023-BYOVD"; CVE tra trên nvd.nist.gov.

*Lưu ý: tên file/driver có thể thay đổi giữa các phiên bản. Bài phản ánh các bản phổ biến ~2009–2025.*

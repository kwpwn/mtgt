# Phân tích kỹ thuật sâu — BOF Network Isolation
# (3 Kỹ thuật, Yêu cầu, Tính ổn định, So sánh phương án)

---

## Mục lục

1. [Bối cảnh: Tại sao cần BOF thay vì process bình thường?](#1-bối-cảnh)
2. [Kỹ thuật 1 — NIC Disable qua cfgmgr32](#2-kỹ-thuật-1--nic-disable-qua-cfgmgr32)
3. [Kỹ thuật 2 — Route Isolation qua IP Forwarding Table](#3-kỹ-thuật-2--route-isolation)
4. [Kỹ thuật 3 — DHCP Release/Renew qua iphlpapi](#4-kỹ-thuật-3--dhcp-releaserenew)
5. [Yêu cầu (Requirements)](#5-yêu-cầu)
6. [Tính ổn định trên các phiên bản Windows](#6-tính-ổn-định-trên-windows)
7. [Phương án tốt hơn / thay thế](#7-phương-án-thay-thế)
8. [Ma trận quyết định — Khi nào dùng kỹ thuật nào?](#8-ma-trận-quyết-định)
9. [Wide-char Variants (`_w`) — Unicode adapter names](#9-wide-char-variants)

---

## 1. Bối cảnh

### Tại sao dùng BOF thay vì spawn process?

Một BOF (Beacon Object File) là file COFF x64 được Cobalt Strike beacon nạp thẳng vào bộ nhớ
của chính tiến trình beacon và thực thi trong thread hiện tại. Không có tiến trình con nào được
tạo ra.

**Tại sao điều này quan trọng?**

| Hành động | Spawn process | BOF |
|-----------|:-------------:|:---:|
| Tạo tiến trình mới | ✓ (bị EDR theo dõi) | ✗ |
| Gọi CreateProcess / ShellExecute | ✓ (dễ detect) | ✗ |
| Xuất hiện trong process tree | ✓ | ✗ |
| Artifact trên disk | Có thể | ✗ |
| Gọi trực tiếp Win32 API trong process | ✗ | ✓ |

EDR (Endpoint Detection & Response) hiện đại theo dõi:
- `CreateProcess` / `NtCreateProcess`
- `cmd.exe /c netsh ...` → command-line logging
- PowerShell script execution

BOF bypass tất cả vì không có process creation event nào.

### Tại sao cần phân biệt C2 adapter?

**Câu hỏi:** Tại sao không disable/isolate tất cả adapter luôn?

**Trả lời:** Beacon giao tiếp với C2 server qua một trong các adapter. Nếu ta cắt adapter đó,
beacon mất kết nối ngay lập tức — nhiệm vụ thất bại và ta mất quyền kiểm soát máy nạn nhân.

Cách xác định C2 adapter:
```
GetBestInterface(C2_IP_as_IPAddr, &ifIndex)
    → ifIndex: interface index mà Windows dùng để route đến C2 IP
GetAdaptersAddresses(...)
    → tìm adapter có IfIndex == ifIndex → đọc AdapterName (GUID)
```

`GetBestInterface` sử dụng routing table của Windows để trả lời "nếu tôi muốn gửi packet đến
IP này, tôi sẽ ra bằng interface nào?" — chính xác 100% với routing table hiện tại.

---

## 2. Kỹ thuật 1 — NIC Disable qua cfgmgr32

### Cơ chế hoạt động

```
cfgmgr32.dll
  ↓
PnP Configuration Manager (kernel-mode: nt!PnPManager)
  ↓
Device node (devnode) trong PnP device tree
  ↓
Miniport driver (e.g., vmxnet3.sys, e1000.sys)
  ↓
NIC hardware
```

`CM_Disable_DevNode(devInst, CM_DISABLE_POLITE | CM_DISABLE_UI_NOT_OK)` gửi
`IRP_MN_QUERY_STOP_DEVICE` → `IRP_MN_STOP_DEVICE` đến device driver thông qua PnP Manager.
Driver dừng xử lý packet, release interrupt, giải phóng DMA buffers.

Sau khi disable:
- Adapter biến mất khỏi `GetAdaptersAddresses` (không còn OperStatus)
- `ipconfig` không hiển thị adapter
- Không có traffic nào qua được hardware

### Tại sao dùng cfgmgr32 thay vì SetupAPI?

**Câu hỏi:** SetupDiGetClassDevsW là API quen thuộc hơn, tại sao không dùng?

**Trả lời:** SetupDiGetClassDevsW trong beacon context trả về 0 device.

Root cause: SetupDi API cần tương tác với `SetupAPI` service và có dependency với window station
(session context). Beacon chạy trong Session 0 (SYSTEM service context), không có window station
thật sự. SetupDi fails silently.

cfgmgr32 dùng PnP RPC bus (`cfgmgr32.dll` → `CfgMgr32` → kernel `PnPRPC`) — không phụ thuộc
window station, hoạt động trong mọi session kể cả Session 0.

Kiểm chứng từ thực tế:
```
SetupDiGetClassDevsW → 0 devices found
CM_Get_Device_ID_ListW → 11 devices found
```

### Tại sao cần CM_LOCATE_DEVNODE_PHANTOM?

**Câu hỏi:** `CM_LOCATE_DEVNODE_PHANTOM` là gì? Sao cần flag này?

**Trả lời:** Một "phantom device" là device đã từng kết nối nhưng hiện tại không có mặt
(physically absent) hoặc đã bị disabled từ trước. PnP Manager vẫn giữ devnode của chúng trong
registry để lưu settings, nhưng chúng không "present" trong current hardware scan.

Nếu không có `CM_LOCATE_DEVNODE_PHANTOM`, `CM_Locate_DevNodeW` sẽ fail trên các adapter
đang ở trạng thái DISABLED — chính những adapter ta cần operate.

Với flag PHANTOM, ta có thể locate và enable lại chúng.

### Tại sao phải đọc NetCfgInstanceId từ registry?

**Câu hỏi:** PnP device ID và network GUID khác nhau thế nào?

**Trả lời:**

PnP Device Instance ID trông như thế này:
```
PCI\VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01\4&2B7C36E&0&00A8
```

Đây là định danh của hardware device trong PnP bus. Nó không dùng được để tìm adapter
trong IP stack của Windows.

`NetCfgInstanceId` là GUID mà Network Configuration Manager gán cho adapter:
```
{4D36E972-E325-11CE-BFC1-08002BE10318}
```

Đây là GUID mà `GetAdaptersAddresses.AdapterName` và `GetAdaptersInfo.AdapterName` trả về.
Ta cần cross-reference giữa hai world (PnP world và TCP/IP world) thông qua key này.

Registry path:
```
HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972...}\000X
    → NetCfgInstanceId = "{ACTUAL-ADAPTER-GUID}"
```

`CM_Open_DevNode_Key(devInst, KEY_READ, 0, RegDisposition_OpenExisting, &hKey, CM_REGISTRY_SOFTWARE)`
mở key này mà không cần hardcode path.

### Tính ổn định

| Windows | Ổn định | Ghi chú |
|---------|:-------:|---------|
| Windows 7 | ✓ | cfgmgr32 có từ XP |
| Windows 10 | ✓ | Tested |
| Windows 11 | ✓ | Same API |
| Windows Server 2016/2019 | ✓ | |
| Windows Core (no GUI) | ✓ | cfgmgr32 dùng PnP RPC, không cần GUI |

**Rủi ro:** Cần `SeLoadDriverPrivilege` hoặc SYSTEM token để disable NIC. Với beacon
chạy dưới SYSTEM, không có vấn đề.

### Nhược điểm

- **Persistent:** NIC bị disable tồn tại qua reboot. Nếu quên re-enable, admin sẽ thấy
  khi họ nhìn vào Device Manager.
- **Noisy tại hardware level:** Event Viewer ghi "Device X was disabled" trong System log
  (Event ID 20001, source: Microsoft-Windows-DriverFrameworks-UserMode)
- **Chỉ hoạt động khi có NIC thứ 2:** Nếu C2 và internet dùng chung 1 NIC, không thể
  disable cái còn lại mà không kill beacon.

---

## 3. Kỹ thuật 2 — Route Isolation

### Cơ chế hoạt động

```
Trước nic-isolate:
    Route table (simplified):
        0.0.0.0/0     → gateway: 192.168.1.1   (default — mọi traffic đi qua đây)
        192.168.1.0/24 → on-link                (local subnet)

    Victim gửi request đến google.com (142.250.x.x):
        1. Windows lookup route table
        2. Không có route cụ thể cho 142.250.x.x
        3. Match với 0.0.0.0/0 → forward đến 192.168.1.1
        4. Gateway 192.168.1.1 forward ra internet ✓

Sau nic-isolate 192.168.1.50:
    Route table:
        192.168.1.50/32 → gateway: 192.168.1.1  (host route đến C2)
        192.168.1.0/24  → on-link               (local subnet — giữ nguyên)
        (0.0.0.0/0 đã bị xóa)

    Victim gửi request đến google.com (142.250.x.x):
        1. Windows lookup route table
        2. Không có route cụ thể cho 142.250.x.x
        3. Không có 0.0.0.0/0 nữa
        4. Windows: "NETWORK UNREACHABLE" — drop packet ✗

    Beacon gửi packet đến 192.168.1.50 (C2):
        1. Windows lookup route table
        2. Match với 192.168.1.50/32 (exact host route)
        3. Forward đến 192.168.1.1 → C2 ✓
```

### Tại sao dùng /32 host route thay vì subnet route?

**Câu hỏi:** Tại sao không giữ lại toàn bộ route /24 của subnet C2?

**Trả lời:** Nếu giữ /24:
```
Victim → 192.168.1.1  (gateway — cùng subnet) → beacon vẫn ra được?
```

Gateway (192.168.1.1) chỉ là router trong cùng subnet. Nếu ta giữ route /24, victim vẫn có
thể reach gateway và qua đó ra internet (gateway sẽ forward). Chỉ /32 đảm bảo *duy nhất* C2 IP
là đích đến hợp lệ trong bảng route.

### Tại sao không dùng InitializeIpForwardEntry?

**Câu hỏi:** MSDN nói phải gọi `InitializeIpForwardEntry` trước `CreateIpForwardEntry2`. Sao
không dùng?

**Trả lời:** `InitializeIpForwardEntry` là **inline function** được define trong `netioapi.h`:

```c
FORCEINLINE VOID InitializeIpForwardEntry(PMIB_IPFORWARD_ROW2 Row) {
    memset(Row, 0, sizeof(MIB_IPFORWARD_ROW2));
    Row->ValidLifetime     = 0xffffffff;
    Row->PreferredLifetime = 0xffffffff;
    Row->Protocol          = RouteProtocolNetMgmt;
    Row->SitePrefixLength  = 255;
}
```

Inline function không tạo ra export symbol trong DLL — không có `__imp_` entry để BOF
import. Ta phải implement lại inline này thủ công trong `init_route_row()`.

### Tại sao cần ROUTE_PROTO_NETMGMT = 3?

**Câu hỏi:** Nếu không set Protocol, sẽ xảy ra gì?

**Trả lời:** `Protocol = 0` → `CreateIpForwardEntry2` trả về `ERROR_INVALID_PARAMETER`.
Windows bắt buộc route phải có một protocol source. `RouteProtocolNetMgmt (3)` nghĩa là
"route này được tạo bởi network management software" — tương đương `route add` command.

Các protocol values khác: 2 = LOCAL (kernel generated), 4 = NETSRP, 9 = OSPF, 11 = BGP...

### Tính ổn định

| Windows | API | Ổn định |
|---------|-----|:-------:|
| Vista+ | `GetIpForwardTable2`, `CreateIpForwardEntry2`, `DeleteIpForwardEntry2` | ✓ |
| XP | Không hỗ trợ (dùng `GetIpForwardTable` / `CreateIpForwardEntry` thay thế) | ✗ |
| Win 7/8/10/11 | ✓ | ✓ |
| Windows Server 2008+ | ✓ | ✓ |

Không cần thêm đặc quyền đặc biệt ngoài các quyền network configuration thông thường của
SYSTEM token.

**Điểm quan trọng:** Route changes KHÔNG persist qua reboot. Windows reload routing table
từ DHCP và static config khi khởi động. Sau reboot, 0.0.0.0/0 sẽ tự quay lại.

### Nhược điểm

- Nếu DHCP lease renew trong khi đang isolated, DHCP client service có thể cố gắng
  cập nhật route table và re-add default gateway. Tùy config DHCP client.
- Nếu victim có static route (không phải DHCP), cần biết trước gateway IP để restore.
  BOF xử lý bằng cách lưu gateway từ C2/32 route khi restore.
- `tracert`/`ping` đến local subnet vẫn hoạt động (subnet route vẫn còn) — victim có thể
  reach các máy trong LAN. Chỉ outbound internet bị cắt.

---

## 4. Kỹ thuật 3 — DHCP Release/Renew

### DHCP Release hoạt động thế nào?

```
Client (Windows)                    DHCP Server (Router/ISP)
    |                                      |
    |─── DHCP RELEASE ─────────────────►  |
    |    (src: current IP, dst: DHCP srv) |
    |    "Tôi không cần IP này nữa"        |
    |                                      |
    |  (Windows xóa IP, gateway, subnet)  |
    |  Adapter → state: no IP             |
    |  (hoặc APIPA 169.254.x.x sau ~30s) |
```

`IpReleaseAddress(pAdapterIndexMap)` thực hiện một UDP packet gửi đến DHCP server.
Sau đó Windows Network Configuration Manager tự động remove IP binding từ adapter.

### Tại sao cần GetInterfaceInfo để Release/Renew?

**Câu hỏi:** `GetAdaptersInfo` đã có đủ thông tin về adapter, tại sao cần thêm
`GetInterfaceInfo`?

**Trả lời:** `IpReleaseAddress` và `IpRenewAddress` không nhận adapter GUID hay index.
Chúng nhận `PIP_ADAPTER_INDEX_MAP` — một struct chứa:
- `Index` (DWORD): interface index
- `Name` (WCHAR[]): tên adapter dạng `\DEVICE\TCPIP_{GUID}`

`GetInterfaceInfo` trả về danh sách `IP_ADAPTER_INDEX_MAP` này. Không có API nào khác trả về
cấu trúc đúng định dạng mà `IpReleaseAddress` cần. Đây là lý do cần cross-reference:

```
GetAdaptersInfo → adapter GUID → tìm trong GetInterfaceInfo.Adapter[i].Name (substring) → 
    IP_ADAPTER_INDEX_MAP → IpReleaseAddress/IpRenewAddress
```

### Tại sao IpRenewAddress blocking?

**Câu hỏi:** `IpRenewAddress` có thể block rất lâu, tại sao không dùng async?

**Trả lời:** `IpRenewAddress` internally triggers DHCP DORA process và wait:
- `DHCPDISCOVER` (broadcast, retry 3 lần × 4 giây = 12 giây nếu không có server)
- `DHCPREQUEST` + wait for `DHCPACK`

BOF chạy trong beacon thread. Nếu BOF block quá lâu:
- Beacon không thể check in với C2
- CS operator nhìn thấy beacon "không responsive"
- Với default sleep 60s, 10-30 giây block không phải vấn đề lớn

Nếu cần non-blocking, phải dùng `IpRenewAddressAsync` (Vista+) hoặc NMP Renew thông qua
COM/WMI — phức tạp hơn nhiều và không nên làm trong BOF.

### APIPA là gì và tại sao nó xuất hiện?

**Câu hỏi:** Sau khi release, tại sao adapter đôi khi tự gán 169.254.x.x?

**Trả lời:** APIPA (Automatic Private IP Addressing) là cơ chế Windows dùng khi:
1. Adapter được cấu hình DHCP
2. Không có DHCP lease hiện tại (hoặc đã release)
3. Windows đã chờ ~30 giây mà không có DHCP response

Windows tự gán IP ngẫu nhiên trong dải `169.254.1.0` - `169.254.254.255` và subnet
`255.255.0.0`. Đây là link-local address — không routable ra internet.

Từ góc độ attacker: APIPA không ảnh hưởng đến mục tiêu (victim vẫn không ra internet được),
nhưng victim có thể còn communicate trong LAN qua link-local.

### Tính ổn định

| API | Windows | Ghi chú |
|-----|---------|---------|
| `GetAdaptersInfo` | 98/Me/2000/XP → 11 | Legacy API, ổn định tuyệt đối |
| `GetInterfaceInfo` | 98/2000 → 11 | Ổn định tuyệt đối |
| `IpReleaseAddress` | 98/2000 → 11 | Ổn định |
| `IpRenewAddress` | 98/2000 → 11 | Ổn định |
| `GetAdaptersAddresses` | XP SP1 → 11 | Cần `_WIN32_WINNT >= 0x0501` |
| `DnsFlushResolverCache` | 2000 → 11 | Ổn định |

### Nhược điểm

- **Kill beacon nếu dùng sai:** Release DHCP trên adapter dùng cho C2 → beacon chết.
  BOF check và skip C2 adapter, nhưng operator phải cung cấp đúng C2 IP.
- **APIPA cảnh báo victim:** 169.254.x.x trong `ipconfig` → admin có kinh nghiệm sẽ thấy
  ngay là có gì đó bất thường.
- **DHCP client service có thể auto-renew:** Dịch vụ DHCP Client (svchost) monitor các
  adapter và có thể tự renew sau một thời gian. Dùng kết hợp với NIC disable để chắc chắn.

---

## 5. Yêu cầu (Requirements)

### Privilege requirements

| Kỹ thuật | Minimum Privilege | Lý do |
|----------|:----------------:|-------|
| `nic-list` / `dhcp-check` | Local User | Chỉ read |
| `dhcp-off` / `dhcp-on` | Local Admin hoặc Service | `IpReleaseAddress` cần quyền trên adapter |
| `nic-off` / `nic-on` | **SYSTEM** | `CM_Disable_DevNode` cần SeLoadDriverPrivilege |
| `nic-isolate` / `nic-restore` | Local Admin | Modify routing table |
| `dhcp-flush` | Local Admin hoặc SYSTEM | `DnsFlushResolverCache` |

**Tại sao cần SYSTEM cho NIC disable?**

`CM_Disable_DevNode` gửi IRP vào kernel stack. Kernel check `SeLoadDriverPrivilege`
trước khi cho phép stop/start device. Privilege này mặc định chỉ có trong Administrators
group và SYSTEM. Với beacon impersonate SYSTEM token, không có vấn đề.

### Network requirements

- Beacon phải có kết nối ổn định đến C2 IP *trước* khi thực hiện bất kỳ isolation nào.
- C2 IP phải có route trong routing table — `GetBestInterface` phải trả về hợp lệ.
- Nếu C2 qua proxy hoặc redirector: C2 IP cần là IP của redirector (địa chỉ beacon
  thực sự connect tới), không phải teamserver backend.

### BOF execution context

- BOF chạy trong beacon thread — không spawn process mới.
- `IpRenewAddress` blocking có thể khiến beacon "unresponsive" trong lúc DHCP handshake.
- BOF không persistent — một lần thực thi xong là done, không có background thread.

---

## 6. Tính ổn định trên Windows

### Ma trận compatibility

| Feature | Win7 | Win8/8.1 | Win10 | Win11 | WinSrv 2016 | WinSrv 2022 |
|---------|:---:|:---:|:---:|:---:|:---:|:---:|
| cfgmgr32 NIC disable | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| GetIpForwardTable2 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| CreateIpForwardEntry2 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| IpReleaseAddress | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| GetAdaptersAddresses | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| DnsFlushResolverCache | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

### Vấn đề tiềm tàng theo phiên bản

**Windows 11 (22H2+):** Smart App Control và Secure Boot enforcement chặt hơn, nhưng không
ảnh hưởng đến Win32 API calls từ beacon đang chạy.

**Windows 10 LTSC vs Consumer:** Không có sự khác biệt về network API.

**ARM64 Windows:** BOF này là x64 — không chạy được trên native ARM64 process. Với ARM64
Windows, cần compile ARM64 variant. WOW64 (x64 emulation) có thể chạy được nhưng không
đảm bảo.

**Windows Hyper-V / Azure:** Route isolation hoạt động tốt. NIC disable trên VM có thể bị
block bởi Hyper-V nếu adapter là synthetic adapter có protection. Cần test.

---

## 7. Phương án Thay Thế

### So sánh toàn diện

#### Option A — Windows Firewall (WFP / netsh)

```
netsh advfirewall firewall add rule name="block all" dir=out action=block
netsh advfirewall firewall add rule name="allow c2" dir=out action=allow remoteip=C2_IP
```

Hoặc dùng Windows Filtering Platform (WFP) API trực tiếp trong BOF:
```c
FwpmEngineOpen0 → FwpmFilterAdd0 → block all outbound except C2
```

| Ưu điểm | Nhược điểm |
|---------|-----------|
| Granular: block theo port, IP, protocol | WFP API phức tạp — ~300 lines code |
| Không cần modify route table | `FwpmEngineOpen0` cần SE_NETWORK_SERVICE_PRIVILEGE |
| Transparent với victim (NIC vẫn UP, có IP) | Firewall rules visible trong Windows Firewall UI |
| Persist qua reboot | Cần cleanup sau khi xong |
| Hoạt động với 1 NIC | Event log ghi FW rule changes |

**Tại sao không dùng?** WFP là API phức tạp nhất trong Windows network stack. Cần
handle filter engine sessions, conditions, layers. Overkill cho mục tiêu CTF. Nhưng
**ổn định hơn** và **subtle hơn** so với route deletion trong môi trường production.

#### Option B — NDIS Lightweight Filter (LWF)

Viết NDIS LWF driver để drop packets ở driver level.

| Ưu điểm | Nhược điểm |
|---------|-----------|
| Hoàn toàn invisible với OS | Cần driver signing (Secure Boot) |
| Block ở kernel — không bypass được | Rất phức tạp |
| Không xuất hiện trong route table hay firewall | Cần kernel debug mode hoặc test signing |

**Tại sao không dùng?** Driver signing requirement trên Windows 10/11 với Secure Boot
làm cho approach này thực tế không khả thi trong CTF context.

#### Option C — DNS Poisoning thay vì network isolation

Thay vì cắt internet hoàn toàn, poison DNS cache để victim không resolve được domain:
```
DnsModifyRecordsInCache → thêm record giả cho tất cả domain → trỏ vào 0.0.0.0
```

| Ưu điểm | Nhược điểm |
|---------|-----------|
| Không cần privilege cao | Victim vẫn reach internet qua IP trực tiếp |
| Subtle — không thay đổi network config | DNS cache có TTL, tự clear |
| Khó detect | Không hiệu quả nếu victim dùng DNS over HTTPS |

**Khi nào hữu ích:** Khi muốn block cụ thể các kết nối qua domain name (EDR, AV phone home)
mà không cắt toàn bộ internet.

#### Option D — IP Stack Manipulation qua NsiSetAllParameters

Vista+ có Network Store Interface (NSI) cho phép modify interface parameters.
Ít được document, nhưng là cách Windows internal thực sự modify IP config.

**Tại sao không dùng?** Undocumented API — hành vi có thể khác nhau giữa các Windows
build, không có public header. Rủi ro cao.

#### Option E — NetBT / SMB disable qua registry

```
HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\{GUID}
    TransportBindName = ""  (xóa binding)
```

**Tại sao không dùng?** Chỉ ảnh hưởng đến NetBIOS, không block HTTP/HTTPS.

### Bảng so sánh tổng hợp

| Phương pháp | Hiệu quả | Stealth | Privilege | Phức tạp | Reversible |
|------------|:--------:|:-------:|:---------:|:--------:|:----------:|
| NIC Disable (cfgmgr32) | ★★★★★ | ★★★ | SYSTEM | ★★ | ✓ (nic-on) |
| Route Isolation | ★★★★★ | ★★★★ | Admin | ★★★ | ✓ (nic-restore) |
| DHCP Release | ★★★ | ★★★ | Admin | ★★ | ✓ (dhcp-on) |
| WFP Firewall | ★★★★★ | ★★★★★ | Admin | ★★★★★ | ✓ |
| NDIS LWF Driver | ★★★★★ | ★★★★★ | SYSTEM+Sign | ★★★★★ | ✓ |
| DNS Poisoning | ★★ | ★★★★★ | Admin | ★★★ | ✓ |

---

## 8. Ma trận Quyết định

### Kịch bản → Kỹ thuật phù hợp

```
Q: Beacon và internet victim dùng CHUNG 1 NIC?
    ├── YES → Dùng Route Isolation (nic-isolate)
    │         KHÔNG dùng nic-off hay dhcp-off
    │
    └── NO (có 2+ NIC) → Dùng NIC Disable (nic-off)
                          DHCP Release thêm cho chắc chắn

Q: Muốn cắt internet nhưng victim vẫn reach LAN được?
    → Route Isolation: xóa 0.0.0.0/0, giữ subnet route

Q: Muốn cắt hoàn toàn kể cả LAN?
    → NIC Disable (nic-off) + Route Isolation kết hợp

Q: Chỉ muốn block EDR phone home (không cắt hết internet)?
    → DNS Poisoning (dhcp-flush + DNS record manipulation)
    → hoặc WFP block cụ thể IP của EDR vendor

Q: Cần stealth tối đa (ít artifact nhất)?
    → Route Isolation: không có device event log, không thay đổi hardware state

Q: Victim có static IP (không dùng DHCP)?
    → dhcp-off không có tác dụng (sẽ skip)
    → dùng nic-off hoặc nic-isolate
```

### Quy trình khuyến nghị cho CTF (1 NIC)

```
1. dhcp-check <C2_IP>          → kiểm tra trạng thái hiện tại
2. nic-isolate <C2_IP>         → cắt internet, giữ beacon
3. dhcp-flush <C2_IP>          → xóa DNS cache (không resolve được gì nữa)
4. [làm việc...]
5. nic-restore <C2_IP>         → khôi phục default route
6. dhcp-check <C2_IP>          → verify đã khôi phục

Nếu cần chắc hơn (2 NIC):
2a. nic-off <C2_IP>            → disable NIC phụ
2b. nic-isolate <C2_IP>        → route isolation trên NIC C2
```

---

## 9. Wide-char Variants (`_w`)

### Vấn đề: tên adapter Unicode trong môi trường thực tế

Bản gốc (`bof_disable_nic.c`, `bof_dhcp.c`) chuyển đổi WCHAR sang char bằng cast trực tiếp:

```c
// BẢN GỐC — sai với non-ASCII
for (int i = 0; name[i] && i < 63; i++)
    out[i] = (char)name[i];   // truncate byte cao → sai với UTF-16
```

Cast `(char)wchar_t` chỉ lấy byte thấp (low byte) của UTF-16 code unit. Với ASCII (code point
< 128) thì đúng. Với ký tự ngoài ASCII — tiếng Việt, Hán, Ả Rập, Cyrillic — byte cao bị bỏ,
kết quả là garbage hoặc chuỗi bị cụt.

Hệ quả: `friendly name` của adapter (ví dụ: `Mạng LAN nội bộ`) xuất hiện sai trong output.
Quan trọng hơn: nếu GUID adapter có dạng `{4D36E972-...}` thì vẫn OK (ASCII), nhưng so sánh
chuỗi trên FriendlyName có thể fail.

### Giải pháp: `WideCharToMultiByte(CP_UTF8)`

Bản `_w` dùng `WideCharToMultiByte` — Windows API chuyển đổi UTF-16 → UTF-8 đúng chuẩn:

```c
static void w2a(const WCHAR *src, char *dst, int dstLen) {
    int r = KERNEL32$WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, dstLen, NULL, NULL);
    dst[dstLen - 1] = '\0';
    if (r <= 0) dst[0] = '\0';
}

static void a2w(const char *src, WCHAR *dst, int dstCch) {
    int r = KERNEL32$MultiByteToWideChar(CP_ACP, 0, src, -1, dst, dstCch);
    dst[dstCch - 1] = L'\0';
    if (r <= 0) dst[0] = L'\0';
}
```

`CP_UTF8` đảm bảo mọi codepoint Unicode được encode đúng thành UTF-8 nhiều byte.
`CP_ACP` khi đọc char-GUID từ IP Helper API — GUID luôn ASCII nên ACP = UTF-8 = OK.

### Dual GUID — lý do cần cả `wGuid` và `aGuid`

Windows IP Helper APIs có sự không nhất quán về encoding:

| API | Field chứa GUID/Name | Encoding |
|-----|---------------------|---------|
| `GetAdaptersAddresses` | `AdapterName` | `char *` (ANSI/ASCII) |
| `GetAdaptersInfo` | `AdapterName` | `char *` |
| `GetInterfaceInfo` | `Adapter[i].Name` | `WCHAR *` (UTF-16, dạng `\DEVICE\TCPIP_{GUID}`) |
| `CM_Open_DevNode_Key` → `RegQueryValueExW` | `NetCfgInstanceId` | `WCHAR *` |

Không có API nào trả về GUID nhất quán một encoding. Giải pháp: `get_c2_guid()` điền cả hai:

```c
void get_c2_guid(DWORD ifIdx, WCHAR *wGuid, int wLen, char *aGuid, int aLen) {
    // Từ GetAdaptersAddresses → AdapterName là char*
    // Copy sang aGuid trực tiếp, convert sang wGuid bằng a2w()
}
```

Mỗi API call dùng đúng loại:
- `str_ieq(a->AdapterName, aC2Guid)` — so sánh char với IP Helper API
- `wstr_ieq(wAdapter, wC2Guid)` — so sánh WCHAR với cfgmgr32

### Helpers `wstr_ieq` / `wstr_has`

```c
static BOOL wstr_ieq(const WCHAR *a, const WCHAR *b) {
    while (*a && *b)
        if (KERNEL32$CharLowerW((LPWSTR)(ULONG_PTR)*a++) !=
            KERNEL32$CharLowerW((LPWSTR)(ULONG_PTR)*b++))
            return FALSE;
    return *a == *b;
}

static BOOL wstr_has(const WCHAR *hay, const WCHAR *needle) {
    // Sliding window substring search (WCHAR)
}
```

`CharLowerW` dùng thay vì `towlower` vì BOF không có CRT. `CharLowerW` là Win32 API,
hoạt động với mọi locale kể cả tiếng Thổ Nhĩ Kỳ (i/İ problem).

### `find_if_map` — không cần buffer trung gian

Bản gốc: `GetInterfaceInfo.Adapter[i].Name` là WCHAR → chuyển thành char → so sánh với char GUID.
Bản `_w`: GUID là WCHAR ngay từ đầu → so sánh WCHAR-WCHAR trực tiếp:

```c
// Gốc — cần 512-byte stack buffer + wchar_to_char conversion mỗi iteration
static PIP_ADAPTER_INDEX_MAP find_if_map(PIP_INTERFACE_INFO pIf, const char *aGuid) {
    char nameBuf[512];
    for (DWORD i = 0; i < pIf->NumAdapters; i++) {
        wchar_to_char(pIf->Adapter[i].Name, nameBuf, sizeof(nameBuf));
        if (str_has(nameBuf, aGuid)) return &pIf->Adapter[i];
    }
    return NULL;
}

// _w — trực tiếp WCHAR, không buffer
static PIP_ADAPTER_INDEX_MAP find_if_map(PIP_INTERFACE_INFO pIf, const WCHAR *wGuid) {
    for (DWORD i = 0; i < pIf->NumAdapters; i++)
        if (wstr_has(pIf->Adapter[i].Name, wGuid)) return &pIf->Adapter[i];
    return NULL;
}
```

### `cm_read_net_guid_w` — zero-conversion path

cfgmgr32 trả về WCHAR. Bản gốc convert WCHAR → char cho `aGuid`. Bản `_w` đọc thẳng vào
WCHAR buffer — không có conversion nào:

```c
// _w: đọc thẳng WCHAR từ RegQueryValueExW
static BOOL cm_read_net_guid_w(DEVINST devInst, WCHAR *outGuid, int cch) {
    HKEY hKey;
    DWORD type, size = (DWORD)(cch * sizeof(WCHAR));
    if (CM_Open_DevNode_Key(...) != CR_SUCCESS) return FALSE;
    ADVAPI32$RegQueryValueExW(hKey, L"NetCfgInstanceId", NULL, &type,
                              (LPBYTE)outGuid, &size);
    ...
}
```

Zero-conversion: cfgmgr32 native WCHAR → trực tiếp compare với wC2Guid (cũng WCHAR).

### Bảng tổng hợp: Gốc vs `_w`

| Layer | Bản gốc | Bản `_w` |
|-------|---------|---------|
| GUID type | `char[64]` duy nhất | `wC2Guid[64]` (WCHAR) + `aC2Guid[64]` (char) |
| Convert WCHAR→char | `(char)wchar` (sai non-ASCII) | `WideCharToMultiByte(CP_UTF8)` |
| Convert char→WCHAR | Không làm | `MultiByteToWideChar(CP_ACP)` |
| String compare | `str_ieq` / `str_has` | `wstr_ieq` / `wstr_has` (WCHAR) |
| find_if_map input | `char *aGuid` + 512B stack buffer | `WCHAR *wGuid`, so sánh trực tiếp |
| cm_read_net_guid | WCHAR → char conversion | WCHAR trực tiếp |
| FriendlyName output | Sai với non-ASCII | UTF-8 đúng |

### Khi nào dùng bản `_w`?

Dùng bản `_w` khi môi trường victim có thể có:
- Adapter FriendlyName tiếng Việt (ví dụ: `Mạng LAN nội bộ`, `Mạng không dây`)
- OS ngôn ngữ tiếng Trung, Nhật, Hàn, Ả Rập, Cyrillic
- VM với adapter name chứa ký tự đặc biệt

Bản gốc đủ dùng khi:
- Môi trường hoàn toàn English
- Không cần hiển thị adapter name Unicode trong output

Về functionality: cả hai bản hoàn toàn giống nhau — chỉ khác ở encoding path.
GUID adapter (`{4D36E972-...}`) luôn là ASCII, nên logic skip C2 adapter không bị ảnh hưởng
bởi encoding. Sự khác biệt chỉ thấy ở `BeaconPrintf` output của FriendlyName.

---

## Câu hỏi Kỹ thuật Chuyên sâu

**Q: Tại sao không dùng `SetupDiSetClassInstallParams` + `DIF_PROPERTYCHANGE` để disable NIC?**

A: Đây là SetupAPI approach. `DIF_PROPERTYCHANGE` với `DICS_DISABLE` cũng gửi PnP IRP tương tự
CM_Disable_DevNode, nhưng SetupAPI cần `SetupAPI` DLL context có window station. Trong Session 0
(beacon context), cùng vấn đề như `SetupDiGetClassDevsW`. cfgmgr32 bypass hoàn toàn.

**Q: GetIpForwardTable2 trả về cả IPv6 routes, tại sao chỉ filter AF_INET?**

A: Beacon trong lab context dùng IPv4. Hơn nữa, nếu filter IPv6 routes và xóa ::0/0 default IPv6
route, victim mất IPv6 connectivity nhưng vẫn có IPv4 internet (dual-stack). Chỉ xử lý IPv4
đơn giản hơn và đủ cho mục tiêu.

**Q: Nếu có nhiều default routes (metric khác nhau), nic-restore có thể restore sai metric không?**

A: Có thể. `action_restore` tạo default route với `metric=1`. Metric gốc có thể là 25, 50, 100...
Hệ quả: sau restore, default route vẫn hoạt động (victim ra internet được) nhưng metric thấp hơn
có thể ảnh hưởng routing trong môi trường multi-homed. Trong CTF single-gateway, không phải vấn đề.
Fix: lưu metric gốc trước khi isolate. Cần state persistence qua BOF calls — không khả thi trong
BOF stateless model.

**Q: Tại sao dùng `CM_DISABLE_POLITE | CM_DISABLE_UI_NOT_OK` thay vì chỉ `CM_DISABLE_POLITE`?**

A: `CM_DISABLE_POLITE` = gửi `IRP_MN_QUERY_STOP_DEVICE` trước, cho phép driver từ chối nếu
device đang busy với critical operation.

`CM_DISABLE_UI_NOT_OK` = không hiển thị bất kỳ UI dialog nào cho user khi disable. Trong
beacon context (Session 0, no window station), nếu PnP Manager cố pop dialog, nó sẽ treo
hoặc fail. Flag này ngăn không cho nó thử.

**Q: Tại sao parse_ipv4 tự viết thay vì dùng inet_addr?**

A: BOF không thể dùng CRT functions (không có runtime). `inet_addr` là từ Winsock2 —
có thể import với `WS2_32$inet_addr`. Tuy nhiên, tự viết parser 15 lines tránh thêm
dependency và dễ hiểu hơn. Hơn nữa, `inet_addr` đã deprecated kể từ Vista (MSDN khuyến
nghị `inet_pton` thay thế).

**Q: Tại sao cần `HEAP_ZERO_MEMORY` trong HeapAlloc?**

A: `GetAdaptersAddresses` và các IP Helper APIs xử lý linked list với pointer fields. Nếu
memory không được zero, garbage pointer values trong các Next pointer fields có thể gây crash
khi iterate. `HEAP_ZERO_MEMORY` đảm bảo tất cả fields ban đầu là 0/NULL.

---

*Tài liệu này được viết cho mục đích nghiên cứu bảo mật và CTF.*

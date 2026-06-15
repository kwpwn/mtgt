# Phân tích Kỹ thuật Cực Sâu — BOF Network Control
# Giải thích từng bit, từng API, từng khái niệm Windows internals

---

# PHẦN 1: BOF LÀ GÌ VÀ NÓ HOẠT ĐỘNG THẾ NÀO

## 1.1 COFF Object File — format của BOF

Khi bạn compile `bof_dhcp.c` bằng MinGW:
```
x86_64-w64-mingw32-gcc -c bof_dhcp.c -o dhcp.x64.obj
```

Kết quả là 1 file COFF (Common Object File Format). Đây KHÔNG phải .exe hay .dll.
Đây là raw object file — intermediate step trong build process.

**Cấu trúc COFF file:**
```
┌─────────────────────────────────┐  offset 0
│  COFF File Header (20 bytes)    │
│  Machine: 0x8664 (AMD64)        │
│  NumberOfSections: 6            │
│  TimeDateStamp: ...             │
│  PointerToSymbolTable: 0x2A00   │
│  NumberOfSymbols: 73            │
├─────────────────────────────────┤
│  Section Headers (40 bytes × 6) │
│  .text  - code                  │
│  .data  - initialized data      │
│  .rdata - read-only data        │
│  .bss   - uninitialized data    │
│  .pdata - exception handling    │
│  .xdata - unwind info           │
├─────────────────────────────────┤
│  Section Data                   │
│  .text: machine code bytes      │
│  .rdata: string literals        │
│  .data: static variables        │
├─────────────────────────────────┤
│  Relocation Tables              │
│  (cho mỗi section)              │
│  Danh sách: offset trong section│
│  cần patch với địa chỉ symbol X │
├─────────────────────────────────┤
│  Symbol Table                   │
│  go, action_check, ...          │
│  __imp_IPHLPAPI$GetBestInterface│
│  __imp_DNSAPI$DnsFlushResolver  │
└─────────────────────────────────┘
```

**Tại sao dùng COFF thay vì .exe?**
- .exe có PE header, import table, có thể bị detect khi drop to disk
- COFF object file không có PE header → không phải executable theo nghĩa truyền thống
- Cobalt Strike load và execute COFF in-memory → không có file trên disk

## 1.2 CS BOF Loader — cách nạp và chạy BOF

Khi operator gõ `nic-list 192.168.163.183` trên CS:

**Bước 1: CNA script gói args**
```javascript
// dhcp.cna
$args = bof_pack($1, "zi", $2, 2);
//              bid   fmt  C2_IP  action
// "z" = null-terminated string (C2_IP)
// "i" = 32-bit integer (action)
```

`bof_pack` tạo binary blob:
```
[4 bytes: length of string] [string bytes + null] [4 bytes: int value]
  0x11 0x00 0x00 0x00        "192.168.163.183\0"    0x02 0x00 0x00 0x00
```

**Bước 2: Beacon nhận task, BOF loader chạy**

BOF loader trong beacon (pseudocode):
```c
// 1. Đọc COFF header
COFF_HEADER *hdr = (COFF_HEADER*)bof_bytes;
// hdr->Machine = 0x8664 → verify AMD64

// 2. Allocate memory cho từng section
for (int i = 0; i < hdr->NumberOfSections; i++) {
    sections[i].mem = VirtualAlloc(NULL, section.SizeOfRawData,
                                   MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(sections[i].mem, bof_bytes + section.PointerToRawData,
           section.SizeOfRawData);
}

// 3. Resolve imports — đây là bước quan trọng nhất
for each symbol in SymbolTable:
    if (symbol.name starts with "__imp_"):
        // Ví dụ: "__imp_IPHLPAPI$GetBestInterface"
        dll_name = "IPHLPAPI"    // trước $
        func_name = "GetBestInterface"  // sau $
        
        hDll = LoadLibraryA(dll_name);
        pFunc = GetProcAddress(hDll, func_name);
        
        // Lưu địa chỉ vào bảng import
        import_table[symbol.index] = pFunc;

// 4. Apply relocations
for each section:
    for each relocation in section.relocations:
        // relocation.offset = vị trí trong .text cần patch
        // relocation.symbol = index trong symbol table
        addr = import_table[relocation.symbol];
        *(DWORD*)(section.mem + relocation.offset) = addr;
        // Bây giờ call instruction trỏ đúng đến WinAPI

// 5. Tìm hàm "go" trong symbol table
go_addr = find_symbol("go");

// 6. Gọi go()
typedef void (*GoFunc)(char*, int);
GoFunc go = (GoFunc)(sections[text_section].mem + go_addr.offset);
go(args_blob, args_len);
```

**Tại sao DECLSPEC_IMPORT quan trọng?**

```c
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetBestInterface(IPAddr, PDWORD);
```

`DECLSPEC_IMPORT` = `__declspec(dllimport)` → compiler biết đây là external symbol,
tạo ra `__imp_IPHLPAPI$GetBestInterface` trong symbol table thay vì `IPHLPAPI$GetBestInterface`.

Nếu không có `DECLSPEC_IMPORT`:
- Compiler tạo symbol `IPHLPAPI$GetBestInterface` (direct call)
- BOF loader không biết đây là import
- Crash khi gọi

## 1.3 BeaconPrintf — gửi output về CS

```c
BeaconPrintf(CALLBACK_OUTPUT, "  IP: %s\n", ipStr);
```

`BeaconPrintf` không phải printf thông thường. Nó:
1. Format string vào internal buffer
2. Encode buffer
3. Gửi về CS teamserver qua beacon's C2 channel
4. Teamserver decode và hiển thị trong console

`CALLBACK_OUTPUT` = text bình thường (màu trắng)
`CALLBACK_ERROR` = error text (màu đỏ)

---

# PHẦN 2: WINDOWS NETWORK STACK — KIẾN TRÚC

## 2.1 Các tầng của Windows network stack

```
┌─────────────────────────────────────────────────────────┐
│  User-mode Applications                                 │
│  (browser, cmd, beacon...)                              │
├─────────────────────────────────────────────────────────┤
│  Winsock (ws2_32.dll)                                   │
│  → connect(), send(), recv(), bind()...                 │
├─────────────────────────────────────────────────────────┤
│  AFD.SYS (Ancillary Function Driver)                    │
│  → Kernel-mode Winsock implementation                   │
├─────────────────────────────────────────────────────────┤
│  TCP/IP Stack (tcpip.sys)                               │
│  → TCP, UDP, IP routing, ARP                            │
│  → Đây là nơi routing table tồn tại                    │
├─────────────────────────────────────────────────────────┤
│  NDIS (Network Driver Interface Specification)          │
│  ndis.sys → interface giữa tcpip.sys và NIC driver     │
├─────────────────────────────────────────────────────────┤
│  Miniport Driver (vmxnet3.sys, e1000.sys...)            │
│  → Driver của card mạng cụ thể                         │
├─────────────────────────────────────────────────────────┤
│  Hardware NIC                                           │
└─────────────────────────────────────────────────────────┘

                    ↕ (quản lý device)
┌─────────────────────────────────────────────────────────┐
│  PnP Manager (nt!PnpManager trong kernel)               │
│  → Quản lý lifecycle của device: start/stop/remove      │
│  → cfgmgr32.dll giao tiếp với PnP Manager qua RPC      │
└─────────────────────────────────────────────────────────┘

                    ↕ (cấu hình IP)
┌─────────────────────────────────────────────────────────┐
│  IP Helper API (iphlpapi.dll)                           │
│  → User-mode interface để đọc/ghi network config        │
│  → Giao tiếp với tcpip.sys qua NsiGetAllParameters,    │
│     DeviceIoControl đến \Device\Tcp...                  │
└─────────────────────────────────────────────────────────┘
```

## 2.2 Packet đi qua stack như thế nào

Khi beacon gửi HTTP request đến C2 server (192.168.163.183):

```
beacon process
    │
    │  connect(sock, "192.168.163.183:80")
    ▼
ws2_32.dll (Winsock)
    │
    │  NtDeviceIoControlFile → \Device\Afd
    ▼
afd.sys (kernel)
    │
    │  TdiConnect → \Device\Tcp
    ▼
tcpip.sys
    │  1. Lookup routing table:
    │     Destination: 192.168.163.183
    │     → Match route 192.168.163.183/32 via 192.168.163.2 (sau isolate)
    │     → hoặc 0.0.0.0/0 via 192.168.163.2 (bình thường)
    │  2. ARP lookup: MAC của 192.168.163.2
    │  3. Build Ethernet frame: src_mac | dst_mac | IP | TCP | data
    ▼
ndis.sys
    │  → Pass frame xuống miniport
    ▼
vmxnet3.sys (NIC driver)
    │  → DMA frame ra NIC hardware
    ▼
NIC hardware → Ethernet cable → router → internet
```

**Khi `nic-isolate` xóa 0.0.0.0/0:**

```
tcpip.sys lookup routing table:
    Destination: 142.250.x.x (google)
    → Không có route cụ thể
    → Không có 0.0.0.0/0
    → Return: STATUS_NETWORK_UNREACHABLE
tcpip.sys gửi lỗi về afd.sys → Winsock → application nhận WSAENETUNREACH
```

**Khi NIC driver bị disable (nic-off):**

```
PnP Manager gửi IRP_MN_STOP_DEVICE đến vmxnet3.sys
vmxnet3.sys:
    → Release DMA buffers
    → Disable NIC interrupt
    → DMA channel đóng
ndis.sys:
    → Remove NIC từ NDIS adapter list
    → Notify tcpip.sys: adapter removed
tcpip.sys:
    → Remove all routes liên quan đến adapter này
    → Remove IP binding
    → Adapter biến mất khỏi network stack
```

---

# PHẦN 3: CFGMGR32 — PnP CONFIGURATION MANAGER

## 3.1 PnP Device Tree

Windows quản lý tất cả hardware qua PnP Device Tree — cây phân cấp:

```
HTREE\ROOT\0  (root)
    │
    ├── ACPI\...  (system board, CPU...)
    │
    ├── PCI\...   (PCI bus)
    │     │
    │     ├── PCI\VEN_15AD&DEV_07B0...  (VMware VMXNET3 NIC)
    │     │     DevInst = 0x001A
    │     │     Status: DN_STARTED (driver running)
    │     │     Problem: 0 (no problem)
    │     │
    │     └── PCI\VEN_8086&DEV_100F...  (Intel E1000 NIC)
    │           DevInst = 0x001B
    │
    └── ROOT\...  (virtual devices)
```

Mỗi node trong cây là một **devnode** (device node), có:
- `DevInst` (DEVINST): 32-bit handle, chỉ valid trong session hiện tại
- `Status`: bitmask của DN_* flags
- `Problem`: mã lỗi CM_PROB_* nếu device có vấn đề

## 3.2 `CM_Get_Device_ID_ListW` — tại sao nó hoạt động trong Session 0

**SetupAPI (không hoạt động trong beacon):**
```
SetupDiGetClassDevsW()
    → Gọi SetupAPI service
    → SetupAPI cần UI context (window station, desktop)
    → Trong Session 0: không có window station thật
    → Trả về INVALID_HANDLE_VALUE hoặc empty set
```

**cfgmgr32 (hoạt động):**
```
CM_Get_Device_ID_ListW()
    → Gọi CfgMgr32.dll
    → CfgMgr32 giao tiếp với PnP Manager qua RPC:
       \PIPE\ntsvcs  (NT Services RPC pipe)
    → PnP Manager chạy trong kernel (không cần UI)
    → Trả về list device IDs
```

PnP RPC không cần window station → hoạt động trong bất kỳ context nào kể cả
service, SYSTEM, Session 0.

## 3.3 `CM_GETIDLIST_FILTER_CLASS` — filter theo device class

Network adapter thuộc **Device Setup Class**:
```
Class Name: Net
Class GUID:  {4D36E972-E325-11CE-BFC1-08002BE10318}
```

Với `CM_GETIDLIST_FILTER_CLASS | 0x200` và GUID này:
```
CM_Get_Device_ID_ListW(L"{4D36E972-E325-11CE-BFC1-08002BE10318}", buf, len, 0x200)
→ Chỉ trả về device IDs của NET class devices
→ Ví dụ 11 devices: physical NICs + virtual adapters
```

Không có flag này (filter = 0, pszFilter = NULL):
```
CM_Get_Device_ID_ListW(NULL, buf, len, 0)
→ Trả về TẤT CẢ PnP devices (có thể 200+)
→ Bao gồm: USB, disk, display, audio, HID...
→ Non-net devices không có NetCfgInstanceId → cm_read_net_guid fails → skip
```

**Tại sao 0x200 không có trên Windows 7?**

Windows 7 SDK định nghĩa:
```c
#define CM_GETIDLIST_FILTER_BITS  0x000001FF
```
Maximum valid flag = 0x1FF. Flag 0x200 = out of range → CR_INVALID_FLAG (0x7).

Windows 8 SDK thêm:
```c
#define CM_GETIDLIST_FILTER_CLASS  0x00000200
#define CM_GETIDLIST_FILTER_BITS   0x000003FF
```

## 3.4 Device Instance ID vs NetCfgInstanceId

**Device Instance ID** (từ CM):
```
PCI\VEN_15AD&DEV_07B0&SUBSYS_07B015AD&REV_01\4&2B7C36E&0&00A8
```
Format: `BusType\HardwareID\InstancePath`
- Identify hardware trên physical bus
- Dùng bởi PnP system để load driver đúng

**NetCfgInstanceId** (từ registry):
```
{7550ABB7-F59D-49BC-BAAB-A3E513741037}
```
- GUID do Network Configuration Manager tạo khi install network driver
- Stable: không đổi kể cả reboot, driver update
- Dùng bởi TCP/IP stack, DHCP client, Winsock để identify adapter

**Registry location:**
```
HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\
    0000\
        NetCfgInstanceId = "{7550ABB7-F59D-49BC-BAAB-A3E513741037}"
        DriverDesc = "Intel(R) 82574L Gigabit Network Connection"
        InfPath = "e1c64x64.inf"
    0001\
        NetCfgInstanceId = "{CC42FC52-...}"  (loopback)
```

`CM_Open_DevNode_Key(devInst, KEY_READ, 0, RegDisposition_OpenExisting, &hKey, CM_REGISTRY_SOFTWARE)`

Tham số `CM_REGISTRY_SOFTWARE (1)` → mở Software key của device:
```
HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972...}\000X
```
(Khác với Hardware key ở `HKLM\SYSTEM\CurrentControlSet\Enum\...`)

## 3.5 `CM_Get_DevNode_Status` — đọc trạng thái device

```c
CM_Get_DevNode_Status(&status, &problem, devInst, 0)
```

**`status`** là bitmask của DN_* flags (kernel struct `DEVNODE.dn_Flags`):
```
DN_ROOT_ENUMERATED  0x00000001  enumerated by root bus
DN_DRIVER_LOADED    0x00000002  driver loaded
DN_ENUM_LOADED      0x00000004  bus driver loaded
DN_STARTED          0x00000008  ← QUAN TRỌNG: device running
DN_MANUAL           0x00000010  manually installed
DN_NEED_TO_ENUM     0x00000020  may need re-enumeration
...
DN_DISABLED         0x00008000  ← cũ, dùng CM_PROB_DISABLED thay
```

**`problem`** là CM_PROB_* code:
```
0                   = no problem (device OK)
CM_PROB_DISABLED    = 0x00000016 (22) ← device bị disabled
CM_PROB_FAILED_POST_START = 0x0000000A ← driver failed after start
CM_PROB_NOT_CONFIGURED    = 0x00000001 ← no driver installed
...
```

**Logic xác định state:**
```c
static int cm_device_state(DEVINST devInst) {
    ULONG status = 0, problem = 0;
    if (CM_Get_DevNode_Status(&status, &problem, devInst, 0) != CR_SUCCESS)
        return -1;  // Không query được → UNKNOWN

    if (problem == CM_PROB_DISABLED)
        return 0;   // Bị disable

    if (status & DN_STARTED)
        return 1;   // Driver đang chạy → ENABLED

    return -1;      // Có trong PnP tree nhưng driver không run → PHANTOM
}
```

**Phantom device là gì?**

Device không có `DN_STARTED` và không có `CM_PROB_DISABLED`:
- Virtual adapter đã xóa nhưng còn trong registry
- USB NIC đã rút nhưng Windows còn nhớ
- Driver install fail
- Hibernation artifact

Phantom device không nên operate (disable/enable) → BOF skip.

## 3.6 `CM_Disable_DevNode` — cơ chế bên trong

```c
CM_Disable_DevNode(devInst, CM_DISABLE_POLITE | CM_DISABLE_UI_NOT_OK)
```

**Luồng trong kernel:**
```
cfgmgr32.dll
    │ RPC call đến PnP Manager
    ▼
nt!PnpDisableDevice()
    │
    ├── Gửi IRP_MN_QUERY_STOP_DEVICE đến driver stack
    │   → vmxnet3.sys kiểm tra: có operation đang pending không?
    │   → Nếu OK: trả về STATUS_SUCCESS
    │   → Nếu busy: có thể return STATUS_UNSUCCESSFUL
    │   (CM_DISABLE_POLITE = hỏi trước, không force stop)
    │
    ├── Gửi IRP_MN_STOP_DEVICE
    │   → vmxnet3.sys:
    │       DMA stop
    │       Interrupt disable
    │       Buffer release
    │       Report: "I'm stopped"
    │
    ├── ndis.sys: NicClosed() notification
    │   → tcpip.sys: remove adapter
    │   → DHCP client: adapter gone
    │
    └── PnP Manager: set problem = CM_PROB_DISABLED
        → Lưu vào registry: DeviceOverrides\...
        → Persist qua reboot
```

**`CM_DISABLE_UI_NOT_OK`:**

Nếu không có flag này, PnP Manager có thể gọi:
```
SHShellMessageBox() hoặc SendMessage(HWND_BROADCAST, ...)
```
Trong Session 0 không có HWND → gọi này sẽ block hoặc crash.
Flag này ngăn mọi UI interaction.

---

# PHẦN 4: IPHLPAPI — IP HELPER API

## 4.1 `GetBestInterface` — routing table lookup

```c
IPHLPAPI$GetBestInterface(destAddr, &ifIdx)
```

Bên trong, hàm này gọi:
```
GetBestInterface
    → NsiGetAllParameters(\Device\Nsi, ...)
    → hoặc DeviceIoControl(\Device\Tcp, IOCTL_TCP_QUERY_INFORMATION_EX, ...)
    → tcpip.sys lookup routing table:
        Longest prefix match cho destAddr
        Return: InterfaceIndex của winning route
```

**Longest prefix match** là thuật toán routing:
```
Route table:
    192.168.163.0/24  via on-link  if=11  ← prefix length 24
    0.0.0.0/0         via 192.168.163.2 if=11  ← prefix length 0

Query: best interface cho 192.168.163.183
    → 192.168.163.183 match 192.168.163.0/24? YES (24 bits match)
    → 192.168.163.183 match 0.0.0.0/0? YES (0 bits match)
    → Longest match wins: /24 → ifIdx = 11
```

## 4.2 `GetAdaptersAddresses` — struct phức tạp nhất

```c
GetAdaptersAddresses(AF_UNSPEC, flags, NULL, pBuffer, &len)
```

Trả về linked list `IP_ADAPTER_ADDRESSES`:

```
IP_ADAPTER_ADDRESSES (adapter 1)
    │
    ├── Next → IP_ADAPTER_ADDRESSES (adapter 2) → ...
    ├── AdapterName: "{7550ABB7-...}" (GUID, ASCII)
    ├── FriendlyName: L"Ethernet0" (Unicode)
    ├── Description: L"Intel(R) 82574L..."
    ├── PhysicalAddress[8]: { 0x00, 0x0C, 0x29, 0xFA, 0xA4, 0x14, 0, 0 }
    ├── PhysicalAddressLength: 6
    ├── IfIndex: 11
    ├── IfType: IF_TYPE_ETHERNET_CSMACD (6)
    ├── OperStatus: IfOperStatusUp (1)
    │
    ├── FirstUnicastAddress → IP_ADAPTER_UNICAST_ADDRESS
    │       Address.lpSockaddr → SOCKADDR_IN
    │           sin_family: AF_INET (2)
    │           sin_addr: { 192, 168, 163, 128 }  ← 4 bytes
    │       Next → ... (multiple IPs possible)
    │
    └── FirstDnsServerAddress → IP_ADAPTER_DNS_SERVER_ADDRESS
            Address.lpSockaddr → SOCKADDR_IN
                sin_addr: { 192, 168, 163, 2 }
            Next → IP_ADAPTER_DNS_SERVER_ADDRESS (2nd DNS)
                ...
```

**Flags quan trọng:**
```c
GAA_FLAG_SKIP_ANYCAST    0x0002  // bỏ qua anycast addresses
GAA_FLAG_SKIP_MULTICAST  0x0004  // bỏ qua multicast
GAA_FLAG_SKIP_DNS_SERVER 0x0008  // BỎ QUA DNS servers
```

Khi cần DNS servers (trong `action_check`):
```c
ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
// KHÔNG có GAA_FLAG_SKIP_DNS_SERVER
```

Khi không cần DNS (trong `get_c2_guid`):
```c
ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
// Thêm SKIP_DNS_SERVER → nhỏ hơn, nhanh hơn
```

## 4.3 `GetAdaptersInfo` — struct đơn giản hơn nhưng có DHCP info

```c
GetAdaptersInfo(pBuffer, &len)
```

Trả về linked list `IP_ADAPTER_INFO`:

```
IP_ADAPTER_INFO
    ├── Next → IP_ADAPTER_INFO → ...
    ├── AdapterName[260]: "{7550ABB7-...}" (ASCII)
    ├── Description[132]: "Intel(R) 82574L..."
    ├── Address[8]: { 0x00, 0x0C, 0x29, ... }  ← MAC bytes
    ├── AddressLength: 6
    ├── DhcpEnabled: 1 (TRUE)
    │
    ├── IpAddressList: IP_ADDR_STRING (linked list)
    │   ├── IpAddress.String: "192.168.163.128"
    │   ├── IpMask.String: "255.255.255.0"
    │   └── Next → ... (multiple IPs)
    │
    ├── GatewayList: IP_ADDR_STRING
    │   └── IpAddress.String: "192.168.163.2"
    │
    └── DhcpServer: IP_ADDR_STRING
        └── IpAddress.String: "192.168.163.254"
```

**Tại sao `GetAdaptersInfo` không dùng cho MAC?**

Thực ra `Address[8]` và `AddressLength` CÓ MAC address. Nhưng `GetAdaptersAddresses`
có `PhysicalAddressLength` rõ ràng hơn và là API modern. BOF dùng `GetAdaptersAddresses`
cho MAC vì đã cần load nó để lấy DNS và FriendlyName anyway.

## 4.4 `GetInterfaceInfo` — tại sao cần cho Release/Renew

```c
GetInterfaceInfo(pBuffer, &len)
```

Trả về `IP_INTERFACE_INFO`:
```
IP_INTERFACE_INFO
    ├── NumAdapters: 2
    └── Adapter[0]: IP_ADAPTER_INDEX_MAP
            Index: 11
            Name[MAX_ADAPTER_NAME]: L"\\DEVICE\\TCPIP_{7550ABB7-F59D-49BC-BAAB-A3E513741037}"
        Adapter[1]: IP_ADAPTER_INDEX_MAP
            Index: 1
            Name: L"\\DEVICE\\TCPIP_{CC42FC52-...}"  (loopback)
```

`IpReleaseAddress(IP_ADAPTER_INDEX_MAP*)` cần struct này vì:
- Internally gọi DHCP client service qua RPC
- DHCP client service identify adapter bằng `\DEVICE\TCPIP_{GUID}` path
- Không phải bằng GUID bare string hay interface index

**`find_if_map` — tại sao dùng substring search:**
```c
// adapter GUID: "{7550ABB7-F59D-49BC-BAAB-A3E513741037}"
// InterfaceInfo Name: L"\\DEVICE\\TCPIP_{7550ABB7-F59D-49BC-BAAB-A3E513741037}"
//
// Không thể dùng str_ieq (equal) vì Name có prefix
// Phải dùng str_has (substring search):
str_has("\\DEVICE\\TCPIP_{7550ABB7-...}", "{7550ABB7-...}") → TRUE
```

## 4.5 DHCP Protocol — IpReleaseAddress bên trong làm gì

**DHCP RELEASE packet (RFC 2131):**
```
UDP packet:
    src: 192.168.163.128:68 (client port)
    dst: 192.168.163.254:67 (DHCP server port)

DHCP payload:
    op:     1 (BOOTREQUEST)
    htype:  1 (Ethernet)
    hlen:   6 (MAC length)
    xid:    [transaction ID]
    ciaddr: 192.168.163.128  ← IP đang dùng
    chaddr: 00:0C:29:FA:A4:14  ← MAC
    options:
        53 (DHCP Message Type): 7 (DHCPRELEASE)
        54 (Server Identifier): 192.168.163.254
        255 (End)
```

Sau khi DHCP server nhận RELEASE:
- Server đánh dấu IP là "available" (có thể cấp cho máy khác)
- Server không gửi reply (DHCP RELEASE là one-way)
- Client (Windows) tự xóa IP binding ngay sau khi gửi

## 4.6 `GetIpForwardTable2` — routing table structure

```c
GetIpForwardTable2(AF_INET, &pTable)
```

Trả về `MIB_IPFORWARD_TABLE2`:
```
MIB_IPFORWARD_TABLE2
    ├── NumEntries: 5
    └── Table[5]: MIB_IPFORWARD_ROW2
```

Mỗi `MIB_IPFORWARD_ROW2` (80 bytes):
```
MIB_IPFORWARD_ROW2:
    InterfaceLuid:   { Value: 0x0000400000000B00 }  ← 64-bit interface ID
    InterfaceIndex:  11
    
    DestinationPrefix:
        Prefix:
            si_family: AF_INET (2)
            Ipv4:
                sin_family: 2
                sin_addr: { 0, 0, 0, 0 }  ← 0.0.0.0 (default route)
        PrefixLength: 0  ← /0 = default
    
    NextHop:
        si_family: AF_INET (2)
        Ipv4:
            sin_addr: { 192, 168, 163, 2 }  ← gateway
    
    SitePrefixLength: 0
    ValidLifetime:    0xFFFFFFFF
    PreferredLifetime:0xFFFFFFFF
    Metric:           25
    Protocol:         RouteProtocolNetMgmt (3)
    Loopback:         FALSE
    AutoconfigureAddress: FALSE
    Publish:          FALSE
    Immortal:         FALSE
    Age:              0
    Origin:           NlroManual
```

**`InterfaceLuid` vs `InterfaceIndex`:**

`InterfaceIndex` thay đổi mỗi lần reboot (dynamic). `InterfaceLuid` là stable identifier
(persist qua reboot). Khi tạo route mới bằng `CreateIpForwardEntry2`, cần set CẢ HAI
vì Windows validate consistency.

**Tại sao check `sin_addr.s_addr == 0` để tìm default route:**

```c
if (row->DestinationPrefix.PrefixLength != 0) continue;  // phải là /0
if (row->DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr != 0) continue;  // dest phải là 0.0.0.0
```

Default route = 0.0.0.0/0. `s_addr` của 0.0.0.0 = 0 trong bất kỳ byte order nào.

---

# PHẦN 5: MEMORY MANAGEMENT KHÔNG CÓ CRT

## 5.1 Tại sao không có malloc/free

BOF là COFF object file — không được link với bất kỳ library nào. Không có:
- `msvcrt.dll` (C runtime)
- `ucrt.dll` (Universal CRT)
- `libgcc` (GCC runtime)

Nếu gọi `malloc`:
- Compiler tạo external symbol reference `malloc`
- BOF loader không biết resolve `malloc` ở đâu
- Import fail → crash

## 5.2 Heap API thay thế

```c
#define HALLOC(n) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (n))
#define HFREE(p)  KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, (p))
```

**`GetProcessHeap()`:** Trả về handle của default heap của process hiện tại.
Mỗi Windows process có ít nhất 1 heap (default heap) được tạo khi process start.

**`HeapAlloc(hHeap, HEAP_ZERO_MEMORY, size)`:**
- Allocate `size` bytes từ heap
- `HEAP_ZERO_MEMORY`: zero tất cả bytes sau alloc
- Return: pointer đến memory, hoặc NULL nếu fail

**Tại sao HEAP_ZERO_MEMORY quan trọng:**

`IP_ADAPTER_ADDRESSES` có linked list pointers (`Next`, `FirstUnicastAddress`...):
```c
typedef struct _IP_ADAPTER_ADDRESSES {
    ...
    struct _IP_ADAPTER_ADDRESSES *Next;  // nếu = garbage → crash khi iterate
    ...
} IP_ADAPTER_ADDRESSES;
```

`GetAdaptersAddresses` điền vào struct từ đầu đến cuối. Nếu memory không zero,
các field không được fill có thể chứa garbage pointer → khi code iterate theo Next
→ access violation crash.

## 5.3 Two-pass allocation pattern

Tất cả IP Helper APIs dùng pattern này:
```c
// Pass 1: lấy size
ULONG len = 0;
GetAdaptersInfo(NULL, &len);  // trả về ERROR_BUFFER_OVERFLOW, len = bytes needed

// Allocate
PIP_ADAPTER_INFO p = (PIP_ADAPTER_INFO)HALLOC(len);

// Pass 2: lấy data
GetAdaptersInfo(p, &len);  // điền data vào buffer
```

Tại sao không dùng fixed-size buffer?
- Số lượng adapter không biết trước
- Mỗi adapter có description string dài ngắn khác nhau
- Dynamic allocation đảm bảo không buffer overflow

---

# PHẦN 6: STRING OPERATIONS KHÔNG CÓ CRT

## 6.1 `parse_ipv4` — tự viết atoi/inet_addr

```c
static DWORD parse_ipv4(const char *s) {
    DWORD r = 0;
    BYTE *b = (BYTE *)&r;  // b trỏ vào từng byte của DWORD r
    for (int i = 0; i < 4; i++) {
        DWORD v = 0;
        while (*s >= '0' && *s <= '9') {
            v = v * 10 + (BYTE)(*s - '0');  // parse decimal number
            s++;
        }
        if (i < 3 && *s == '.') s++;  // skip '.'
        b[i] = (BYTE)v;  // lưu octet thứ i
    }
    return r;
}
```

**Byte order quan trọng:**

Với "192.168.163.183":
- i=0: v=192, b[0]=192 (byte thấp nhất của DWORD r)
- i=1: v=168, b[1]=168
- i=2: v=163, b[2]=163
- i=3: v=183, b[3]=183

Memory layout của r (little-endian x64):
```
Address:  &r+0  &r+1  &r+2  &r+3
Value:     192   168   163   183
Hex:       C0    A8    A3    B7
```

DWORD value: 0xB7A3A8C0

`GetBestInterface` nhận `IPAddr = DWORD` trong network byte order.
Network byte order = big-endian = bytes theo thứ tự [192, 168, 163, 183].

Trên x86 little-endian: DWORD được đọc ngược = 0xC0A8A3B7... 

Thực ra `inet_addr("192.168.163.183")` trả về 0xB7A3A8C0 (little-endian representation
of network byte order). Và `parse_ipv4` của ta cũng trả về 0xB7A3A8C0. Match!

## 6.2 `fmt_mac` — format MAC address

```c
static void fmt_mac(const BYTE *addr, UINT len, char *out) {
    static const char hx[] = "0123456789ABCDEF";
    int p = 0;
    for (UINT i = 0; i < len && i < 6; i++) {
        if (i > 0) out[p++] = '-';
        out[p++] = hx[(addr[i] >> 4) & 0xF];  // high nibble
        out[p++] = hx[ addr[i]       & 0xF];  // low nibble
    }
    out[p] = '\0';
}
```

Với `addr = {0x00, 0x0C, 0x29, 0xFA, 0xA4, 0x14}`:
- i=0: byte=0x00, high=0, low=0 → "00"
- i=1: byte=0x0C, high=0, low=C → "-0C"
- i=2: byte=0x29, high=2, low=9 → "-29"
- ...
- Kết quả: "00-0C-29-FA-A4-14"

**`static const char hx[]`:**

`static` ở local scope → variable tồn tại trong `.rdata` section của COFF (read-only data).
CS BOF loader map `.rdata` section vào memory. Địa chỉ được patch bởi relocation table.

## 6.3 `str_ieq` — case-insensitive equal

```c
static BOOL str_ieq(const char *a, const char *b) {
    while (*a && *b) {
        char ca = (*a >= 'a' && *a <= 'z') ? (char)(*a - 32) : *a;
        char cb = (*b >= 'a' && *b <= 'z') ? (char)(*b - 32) : *b;
        if (ca != cb) return FALSE;
        a++; b++;
    }
    return (*a == '\0' && *b == '\0');
}
```

Dùng để so sánh GUID: `{7550abb7-...}` với `{7550ABB7-...}`.

`GetAdaptersInfo.AdapterName` có thể lowercase, `GetAdaptersAddresses.AdapterName`
có thể uppercase → cần case-insensitive compare.

Tự viết thay vì `_stricmp` (CRT) hay `CompareStringA` (kernel32 — có thể dùng nhưng
cần thêm import).

---

# PHẦN 7: DNS FLUSH — DnsFlushResolverCache

## 7.1 DNS Resolver Cache hoạt động thế nào

```
Application: gethostbyname("google.com")
    ↓
Winsock → DNS Client service (svchost, dnscache)
    ↓
DNS Client check local cache:
    Nếu có entry "google.com" → A → 142.250.x.x: return từ cache
    Nếu không có: query DNS server (192.168.163.2)
        → DNS server trả về IP
        → Cache entry với TTL
        → Return IP cho application
```

**Tại sao flush sau nic-isolate?**

Sau `nic-isolate`, victim không có default route → không ra internet.
NHƯNG: nếu victim vừa browse google.com 1 phút trước, DNS cache còn entry:
```
google.com → 142.250.x.x  (TTL còn 290 giây)
```

Application có thể:
1. Resolve google.com → lấy IP từ cache (không cần DNS server)
2. Kết nối đến 142.250.x.x → FAIL (không có route) → OK ta cắt được

Thực ra sau isolate, dù có IP trong cache, connection cũng fail vì không có route.
Nhưng flush DNS đảm bảo victim không biết IP nào để thử → fail ngay ở bước resolve.

## 7.2 `DnsFlushResolverCache` — bên trong

```
DnsFlushResolverCache() trong dnsapi.dll
    → RPC call đến DNS Client service (svchost, group: LocalServiceNetworkRestricted)
    → DNS Client service clear in-memory cache
    → Return TRUE nếu success
```

**Tại sao cần Admin/SYSTEM?**

DNS Client service chạy với `LocalService` account. Để clear cache của nó qua RPC,
caller cần quyền thích hợp. Với SYSTEM token → đủ quyền.

---

# PHẦN 8: CNA (COBALT STRIKE AGGRESSOR SCRIPT)

## 8.1 `bof_pack` format string

```javascript
$args = bof_pack($1, "zi", $2, 2);
```

Format characters:
```
b = byte[]  (binary blob, với length prefix)
i = int32   (4 bytes, little-endian)
s = int16   (2 bytes, little-endian)
z = string  (null-terminated, với length prefix 4 bytes)
Z = wstring (wide string, null-terminated, với length prefix)
```

Binary layout của `bof_pack($1, "zi", "192.168.163.183", 2)`:
```
Bytes:
[11 00 00 00]  ← length của string (17 bytes including null)  WAIT
Thực ra:
[10 00 00 00]  ← 16 bytes (15 chars + 1 null)
[31 39 32 2E 31 36 38 2E 31 36 33 2E 31 38 33 00]  ← "192.168.163.183\0"
[02 00 00 00]  ← int32 = 2 (action)
```

## 8.2 `BeaconDataParse` / `BeaconDataExtract` / `BeaconDataInt`

Trong `go()`:
```c
datap parser;
BeaconDataParse(&parser, args, len);
// parser.original = args
// parser.buffer = args
// parser.length = len
// parser.size = len

char *c2ip = BeaconDataExtract(&parser, NULL);
// Đọc [4-byte length] rồi trả về pointer vào args + 4
// Advance parser.buffer

int action = BeaconDataInt(&parser);
// Đọc [4-byte int] little-endian
// Advance parser.buffer
// Return int value
```

`BeaconDataExtract` trả về pointer INTO args buffer — không allocate memory mới.
Đó là lý do không cần free c2ip.

---

# PHẦN 9: TẠI SAO KHÔNG DÙNG WMI

## 9.1 WMI architecture

```
WMI Application (VBScript, PowerShell, C++)
    ↓ COM
WMI Service (winmgmt, svchost)
    ↓ RPC/DCOM
WMI Provider Host (WmiPrvSE.exe) ← đây là separate PROCESS
    ↓
WMI Provider DLL (ncprov.dll cho network...)
    ↓
Win32_NetworkAdapter.Disable() → gọi SetupAPI / devmgr
```

**Vấn đề 1: Cần COM**

```c
// Trong BOF phải:
OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
OLE32$CoCreateInstance(&CLSID_WbemLocator, ...);
// IWbemLocator::ConnectServer(L"root\\cimv2", ...)
// IWbemServices::ExecQuery(L"SELECT * FROM Win32_NetworkAdapter WHERE ...")
// IEnumWbemClassObject::Next(...)
// IWbemClassObject::Get(L"Index", ...)
// IWbemServices::ExecMethod(L"Win32_NetworkAdapter.DeviceID='...'", L"Disable", ...)
```

Đây là 50+ lines of COM boilerplate chỉ để disable 1 NIC.

**Vấn đề 2: Spawn WmiPrvSE.exe**

WMI tạo `WmiPrvSE.exe` (WMI Provider Service) — process riêng biệt. EDR thấy:
```
beacon.exe → spawns → WmiPrvSE.exe
```
Process creation event → EDR alert.

**Vấn đề 3: Event logging**

Windows ghi WMI activity vào:
- Event Log: Microsoft-Windows-WMI-Activity/Operational
- Prefetch: WmiPrvSE.exe-xxxxx.pf

**Vấn đề 4: Chậm hơn**

WMI query mất 100-500ms. cfgmgr32 direct call mất < 1ms.

**Kết luận:** WMI = overkill + noisy + chậm. Win32 API trực tiếp làm được mọi thứ
WMI làm, nhanh hơn, không tạo process mới, không có event log.

---

# PHẦN 10: COMPILE — TẠI SAO MINGW, KHÔNG PHẢI MSVC

## 10.1 Vấn đề của MSVC với BOF

MSVC tạo các symbol đặc biệt cho string literals trong ternary expression:
```c
// MSVC compile:
const char *s = (x > 0) ? "yes" : "no";
// → Tạo symbol $SG89335 trong COMDAT section
// → BOF loader không biết resolve $SG89335
// → Import fail
```

MSVC cũng có thể tạo machine type 0x3A43 (ARM Thumb) thay vì 0x8664 (AMD64)
nếu cấu hình không đúng → BOF loader reject.

## 10.2 MinGW-w64 hoạt động đúng

```
x86_64-w64-mingw32-gcc
    → Target: x86_64-w64-mingw32 (Windows 64-bit)
    → Output machine: 0x8664 (AMD64) ← đúng
    → Không tạo $SG symbols
    → Không link CRT (với -c flag, chỉ compile không link)
    → Output: COFF object file thuần túy
```

Flag `-fno-asynchronous-unwind-tables`:
- Không tạo `.eh_frame` section (exception handling frame)
- BOF không cần exception handling → giảm size
- Tránh các section BOF loader không biết handle

Flag `-masm=intel`:
- Intel syntax cho inline assembly (nếu có)
- Nhất quán với Windows x64 ABI

---

---

# PHẦN 11: TẠI SAO NIC DISABLE TỐT HƠN IPCONFIG /RELEASE

## 11.1 Chúng tác động ở tầng khác nhau

```
┌─────────────────────────────────────────────────────┐
│  Tầng 3 — IP Layer (tcpip.sys)                      │
│  → ipconfig /release tác động ĐÂY                   │
│  → Chỉ xóa IP address binding                       │
│  → Driver vẫn chạy, hardware vẫn nhận signal        │
│  → DHCP Client service vẫn thấy adapter              │
├─────────────────────────────────────────────────────┤
│  Tầng 2 — Data Link (NDIS, ndis.sys)                │
├─────────────────────────────────────────────────────┤
│  Tầng 1 — Physical/Driver (vmxnet3.sys, e1000.sys)  │
│  → NIC disable tác động ĐÂY                         │
│  → Driver bị stop hoàn toàn                         │
│  → Adapter biến mất khỏi mọi thứ                    │
└─────────────────────────────────────────────────────┘
```

## 11.2 ipconfig /release — chỉ xóa IP, driver vẫn sống

Sau `ipconfig /release`:

```
vmxnet3.sys (NIC driver)     → vẫn RUNNING ✓
ndis.sys                     → vẫn thấy adapter ✓
tcpip.sys                    → adapter vẫn present ✓
IP address trên adapter      → BỊ XÓA ✗
DHCP Client service          → vẫn thấy adapter ✓ ← VẤN ĐỀ
```

**DHCP Client service (svchost.exe, group: LocalServiceNetworkRestricted):**

Service này chạy ngầm 24/7, nhiệm vụ là monitor tất cả adapter trong hệ thống.
Khi nó phát hiện adapter có `DhcpEnabled = TRUE` nhưng không có IP:

```
DHCP Client service logic (pseudocode):
    for mỗi adapter trong system:
        if adapter.DhcpEnabled == TRUE:
            if adapter.CurrentIP == 0.0.0.0:  ← không có IP
                trigger DHCP DISCOVER
                    → broadcast UDP đến 255.255.255.255:67
                    → chờ DHCP OFFER từ server
                    → gửi DHCP REQUEST
                    → nhận DHCP ACK
                    → set IP trở lại
```

**Timeline sau ipconfig /release:**
```
T+0s:   IP bị xóa. Victim mất mạng.
T+5s:   DHCP Client service phát hiện adapter không có IP
T+10s:  DHCP DISCOVER broadcast gửi đi
T+15s:  DHCP server cấp IP mới (hoặc IP cũ nếu lease còn)
T+20s:  Victim có IP lại. Mạng khôi phục tự động.
```

Victim **không cần làm gì** — Windows tự fix.

## 11.3 NIC disable — driver bị stop, không thể auto-recover

Sau `CM_Disable_DevNode`:

```
PnP Manager gửi IRP_MN_STOP_DEVICE đến vmxnet3.sys
    ↓
vmxnet3.sys:
    - Release tất cả DMA buffers
    - Disable interrupt từ hardware
    - Ngắt kết nối DMA channel
    - Báo cáo: "device stopped"
    ↓
ndis.sys nhận NicClosed():
    - Xóa adapter khỏi NDIS adapter list
    - Notify tất cả protocol drivers (tcpip.sys...)
    ↓
tcpip.sys:
    - Remove tất cả IP bindings của adapter
    - Remove tất cả routes liên quan
    - Xóa ARP cache của interface
    ↓
DHCP Client service:
    - Phát hiện adapter bị remove
    - Không làm gì (không có adapter để renew)
    ↓
Kết quả:
    - Adapter KHÔNG còn trong GetAdaptersAddresses
    - Adapter KHÔNG còn trong ipconfig
    - DHCP Client KHÔNG thể renew (không có nơi để renew)
    - Victim KHÔNG thể tự recover
```

**Timeline sau NIC disable:**
```
T+0s:    Driver stop. Victim mất mạng.
T+30s:   DHCP Client service check... adapter không còn tồn tại.
T+60s:   Vẫn không có adapter.
T+reboot: Nếu không chạy nic-on, NIC vẫn disabled sau reboot.
```

Victim **không thể tự recover** — cần người vào Device Manager enable lại bằng tay,
hoặc BOF `nic-on`.

## 11.4 So sánh trực tiếp từng góc độ

### Về độ bền (persistence)

| | ipconfig /release | NIC disable |
|--|--|--|
| Sau 30 giây | DHCP auto-renew → victim có IP lại | Vẫn disabled |
| Sau 5 phút | Hoàn toàn khôi phục tự động | Vẫn disabled |
| Sau reboot | IP được DHCP cấp lại khi boot | **Vẫn disabled** (PnP lưu state vào registry) |

NIC disable **persist qua reboot** vì PnP Manager lưu trạng thái disable vào registry:
```
HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_...\4&...\
    ConfigFlags: 0x00000001  ← bit 0 = CONFIGFLAG_DISABLED
```
Mỗi lần boot, PnP Manager đọc registry → thấy device bị disable → không load driver.

### Về tầng tác động

```
ipconfig /release:
    Chỉ tác động TCP/IP stack layer
    → Hardware vẫn nhận Ethernet signal
    → NDIS vẫn thấy adapter
    → Chỉ IP layer không có địa chỉ

NIC disable:
    Tác động từ driver layer trở lên
    → Hardware có điện nhưng driver không giao tiếp
    → NDIS không thấy adapter
    → TCP/IP không thấy adapter
    → Không thể có IP trên adapter không tồn tại
```

### Về khả năng auto-recover

**ipconfig /release — tại sao tự recover được:**

DHCP Client service (services.msc: "DHCP Client") chạy độc lập với IP state.
Nó monitor adapter existence (adapter vẫn còn) chứ không monitor IP state.
Khi thấy adapter tồn tại + DHCP enabled + không có IP → tự renew.

**NIC disable — tại sao KHÔNG tự recover:**

DHCP Client service monitor adapter list. Sau khi disable:
- Adapter biến khỏi list (không còn trong NDIS adapter list)
- DHCP Client service: "không có adapter nào cần renew"
- Không làm gì cả

Để recover: phải có external action (Device Manager, `nic-on` BOF, hoặc reboot nếu
ConfigFlags không bị set — nhưng NIC disable sẽ còn sau reboot).

### Về stealth / detectability

**ipconfig /release:**
```
Event Log: KHÔNG có event đặc biệt
Network Monitor: thấy DHCP RELEASE packet trên wire
Victim experience: mất mạng ~20 giây rồi tự lấy lại
→ Victim có thể nghĩ "mạng bị giật" → ít nghi ngờ
```

**NIC disable:**
```
Event Log:
    System → Event ID 20001
    Source: Microsoft-Windows-DriverFrameworks-UserMode
    "Device Intel(R) 82574L... was stopped"

Device Manager: NIC hiển thị dấu ↓ màu vàng (disabled)
Victim experience: Network icon mất hoàn toàn → nghi ngờ hơn
```

NIC disable **noisier** hơn về mặt event log, nhưng **hiệu quả hơn** về mặt persistence.

### Về use case

```
Muốn cắt mạng ngắn (< 1 phút), victim không để ý:
    → ipconfig /release đủ dùng
    (nhưng victim tự recover, không kiểm soát được)

Muốn cắt mạng dài, victim không tự recover:
    → NIC disable (nic-off)
    (mạnh hơn, nhưng noisy hơn trong event log)

Muốn cắt mạng nhưng stealth tối đa:
    → Route isolation (nic-isolate)
    (không có event log, không thay đổi hardware state,
     victim vẫn thấy NIC UP nhưng không ra được internet)
```

## 11.5 Kết hợp cả hai — tốt nhất

Trong `nic-off` BOF, ta dùng **cả hai** theo thứ tự:

```c
// Bước 1: DHCP release trước
release_dhcp(devGuid, pIfInfo);  // IpReleaseAddress
// → Báo DHCP server trả lại IP (clean)

// Bước 2: Disable NIC
CM_Disable_DevNode(devInst, CM_DISABLE_POLITE | CM_DISABLE_UI_NOT_OK);
// → Driver stop, adapter biến mất
```

**Tại sao release trước, disable sau?**

Nếu disable mà không release:
- DHCP server vẫn "nghĩ" IP 192.168.163.128 đang được dùng
- IP bị "lock" trong DHCP lease table cho đến hết lease time (ví dụ 24h)
- Khi enable lại, DHCP server có thể từ chối cấp IP cũ (đã hết trong pool)
- Hoặc cấp IP khác → network config thay đổi

Release trước → DHCP server biết IP được trả → khi enable lại nhận đúng IP cũ.

*Tài liệu này giải thích toàn bộ kỹ thuật từ COFF format, Windows kernel internals,
đến từng byte trong packet DHCP. Mục đích: nghiên cứu bảo mật và CTF.*

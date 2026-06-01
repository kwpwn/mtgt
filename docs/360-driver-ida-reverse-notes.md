# Ghi chú dịch ngược driver 360 bằng IDA

Cập nhật: 2026-06-02

Corpus nguồn:

```text
E:\temp\360_reverse_CTF
```

Phạm vi: chỉ phân tích các driver `360*.sys`. Những driver không thuộc 360 trong cùng thư mục đã được bỏ qua.

Phương pháp:

- Thử attach trực tiếp bằng `ida-mcp` trước. Trong lần chạy này, plugin IDA cục bộ không mở được RPC instance trực tiếp.
- Cấu hình IDAPython bằng `idapyswitch`.
- Chạy IDA headless (`idat.exe`) trên các database `.i64` có sẵn và xuất JSON bằng `scripts/ida_export_360_driver.py`.
- Artifact xuất ra nằm trong `reports/ida_360/*.json`.

Ghi chú an toàn: tài liệu này ghi lại vai trò driver, bề mặt callback/minifilter/WFP và các hướng nghiên cứu phòng thủ. Tài liệu cố ý không ghi công thức khai thác, chi tiết trigger IOCTL hoặc các bước bypass.

## 1. Danh mục driver

| Driver | Kích thước | Timestamp | Bên ký | SHA-256 |
|---|---:|---|---|---|
| `360AntiAttack64.sys` | 80,592 | 2022-10-24 | Beijing Qihu Technology | `66C197CB7F4859ADD8724414C8530AEC9762E0F860779BA0D30D2E84C2BA8877` |
| `360AntiHacker64.sys` | 200,944 | 2024-03-04 | Microsoft Windows Hardware Compatibility Publisher | `5EC905B5C074E55E5D5CFFCBAB7A7120CBE09F6420053C902FD653791DE47BEB` |
| `360AntiHijack64.sys` | 112,200 | 2025-02-12 | Microsoft Windows Hardware Compatibility Publisher | `2A25A721E4FE6B766CA0E0A132A6DE6933C2FD271353872065E81DA1E73D5CCA` |
| `360AntiSteal64.sys` | 55,368 | 2025-02-28 | Microsoft Windows Hardware Compatibility Publisher | `63CF4D653E1B85C3D190ABD32BA140F1FDD9771F30199ECBE2088EA43C03AA1D` |
| `360Box64.sys` | 352,344 | 2025-02-28 | Microsoft Windows Hardware Compatibility Publisher | `6159F26CB0108E858B4935A8A868EBBAD1756E389DAF51354C28DB47CACF0B4D` |
| `360Camera64.sys` | 58,200 | 2023-03-17 | Beijing Qihu Technology | `B004E8E86E2FDF24A94237D9BDB42DA1BCBFE3AEECCE927C4EF2604A704758F7` |
| `360elam64.sys` | 18,048 | 2023-03-15 | Microsoft Windows Early Launch Anti-malware Publisher | `CFA71FF2E86183B1DFBB093C13DEB73BA7CC33153B74DFB1B06839F16CA684AC` |
| `360FsFlt.sys` | 591,600 | 2026-05-12 | Microsoft Windows Hardware Compatibility Publisher | `12F566D4ED74BBE897777606679FE450CF07CDE79F3EF11C9C1964F8AFD10D8D` |
| `360Hvm64.sys` | 460,056 | 2025-08-18 | Microsoft Windows Hardware Compatibility Publisher | `F89D5D95B8A59E6D5E50A49217F83D080E4EAF4BB77B80D8F38CD915640BA124` |
| `360netmon.sys` | 110,360 | 2026-05-12 | Microsoft Windows Hardware Compatibility Publisher | `B9805D4707E9D24E01C37A7FA76E0412B04EF6685A2C31D182706170957065AB` |
| `360qpesv64.sys` | 346,824 | 2025-05-27 | Microsoft Windows Hardware Compatibility Publisher | `2D86BFB596BB6B25D527B1C6000DA645F7C66D9CAF108D3959DCF67C1DC06602` |
| `360Sensor64.sys` | 53,520 | 2022-03-03 | Beijing Qihu Technology | `1A602738005941F139C996B01E46F6028F5E9CA487C10451A14B3CF0B4FA630E` |

## 2. Bản đồ tổng quan

| Driver | Bề mặt quan sát được trong IDA | Vai trò nhiều khả năng |
|---|---|---|
| `360FsFlt.sys` | `FltRegisterFilter`, callback communication port, `ObRegisterCallbacks`, notify process/thread/image, callback registry, `\??\PhysicalDrive%d`, chuỗi liên quan `rules.c`, `dllcache.c`, `rpcblock.c`, `hookwritembr.c`, `exploitcap\capfilters.c` | Bộ lọc chính cho self-protection và chính sách file-system |
| `360Box64.sys` | Minifilter + communication port + `ObRegisterCallbacks` + process notify + registry callback; chuỗi `x64_360box_mult_sys`, `360filter.c`, `adrules.c`, `360se.exe`, `360sess.exe` | Bộ lọc sandbox/cô lập file-system và helper chính sách process |
| `360qpesv64.sys` | Minifilter + communication port + `PsSetCreateProcessNotifyRoutineEx` + image notify + registry callback; tham chiếu `360FsFlt.sys`, `360netmon.sys`, `360boost64.sys`, `360reskit64.sys`, `360SelfProtection64.sys`, `360Box64.sys`, `360AntiHacker64.sys`, `360qpesv64.sys` và `\??\PhysicalDrive%d` | Driver dịch vụ bảo vệ sản phẩm, sensor sự kiện hoặc quarantine/process-event |
| `360Hvm64.sys` | `MmMapIoSpace`, process/image notify, nhiều chuỗi tên syscall `Nt*Process`/`Nt*Thread`, stub thông điệp thread win32k | Lớp bảo vệ gần hypervisor/HVM, tập trung vào sự kiện nhạy cảm về process/thread/memory |
| `360netmon.sys` | Chuỗi và API WFP: `Fwpm*`, `Fwps*`, `NetLimitWfpAddFilters`, `NetLimitWfpAddCallouts`, chuỗi lỗi callout/register/filter; process notify + registry callback | Driver giám sát mạng / WFP callout |
| `360AntiAttack64.sys` | API WFP callout/filter/stream injection; path PDB nhắc `360antiattack_360sqlprotect_cve_smbv1` | Bảo vệ tấn công mạng, nhiều khả năng có nguồn gốc bảo vệ SMBv1/SQL |
| `360AntiHacker64.sys` | API liệt kê/thêm/xóa WFP provider/filter/callout; process notify | Lớp mạng anti-hacker/WFP |
| `360AntiHijack64.sys` | API WFP stream/transport injection; `doh.360.cn`; process notify | Bảo vệ DNS/web hijack và lọc/chuyển hướng mạng |
| `360AntiSteal64.sys` | Minifilter + communication port + process notify; chuỗi cho routine registry; tên hàm `SafePostCallback`, `IsProcessProtected` | Bộ lọc chống đánh cắp/bảo vệ dữ liệu |
| `360Camera64.sys` | Device driver, chuỗi truy vấn/attach process; không thấy import minifilter/WFP | Bảo vệ truy cập webcam/thiết bị |
| `360elam64.sys` | `IoRegisterBootDriverCallback`, `IoUnregisterBootDriverCallback`; signer ELAM publisher | Bộ phân loại boot Early Launch Anti-Malware |
| `360Sensor64.sys` | Device driver nhỏ với bề mặt device/symlink cơ bản; PDB `360sensorx64.sys` | Helper sensor/telemetry nhẹ; vai trò chính sách chính xác chưa rõ |

## 3. Phát hiện về self-protection

`360FsFlt.sys` là xác nhận cục bộ mạnh nhất cho các writeup công khai:

- Đây là một minifilter (`FltRegisterFilter`, `FltStartFiltering`, `FltCreateCommunicationPort`).
- Driver đăng ký các đường quan sát object, process, thread, image và registry:
  - `ObRegisterCallbacks`
  - `PsSetCreateProcessNotifyRoutine`
  - `PsSetCreateThreadNotifyRoutine`
  - `PsSetLoadImageNotifyRoutine`
  - `CmRegisterCallback`
- Chuỗi/path PDB của driver có các module thiên về chính sách:
  - `rules.c`
  - `dllcache.c`
  - `protectiecom.c`
  - `rpcblock.c`
  - `hookwritembr.c`
  - `exploitcap\capfilters.c`
- Driver tham chiếu `\??\PhysicalDrive%d`, phù hợp với các hook chính sách nhạy cảm ở tầng disk/MBR thấp.
- Driver tham chiếu tên process sản phẩm như `360tray.exe`.

Điều này củng cố mô hình:

```text
360FsFlt.sys
  -> trung gian file-system
  -> chính sách bảo vệ sản phẩm/self-protection
  -> khả năng quan sát process/thread/image/registry
  -> communication port với user-mode
```

## 4. Phát hiện về bảo vệ mạng

Một số driver dùng WFP khá nặng:

- `360netmon.sys`
- `360AntiAttack64.sys`
- `360AntiHacker64.sys`
- `360AntiHijack64.sys`

Bề mặt WFP quan sát được trong IDA gồm:

- `FwpmEngineOpen`
- `FwpmFilterAdd` / `FwpmFilterDelete*`
- `FwpmCalloutAdd` / `FwpmCalloutDelete*`
- `FwpsCalloutRegister*`
- `FwpsStreamInjectAsync`
- `FwpsInjectTransportSendAsync`
- `FwpsInjectTransportReceiveAsync`
- `FwpsFlowAssociateContext`
- `FwpsFlowRemoveContext`

Điều này xác nhận lớp bảo vệ mạng của 360 có các tầng WFP callout/filter trong kernel.

`360AntiHijack64.sys` chứa `doh.360.cn`, đây là một đầu mối tĩnh hữu ích cho nghiên cứu DNS-over-HTTPS hoặc bảo vệ chống DNS hijack. Chỉ nên xem nó là đầu mối, không phải tuyên bố đầy đủ về giao thức.

## 5. Sandbox và cô lập

`360Box64.sys` có bề mặt khá rộng:

- Minifilter và communication port.
- Process callback và registry callback.
- `ObRegisterCallbacks`.
- Các hàm thao tác file như `FltCreateFileEx2`, `FltQueryDirectoryFile`, `FltReadFile`, `FltWriteFile`, `FltSetInformationFile` và thao tác security-object.
- Chuỗi `360se.exe` và `360sess.exe`.
- Path PDB `x64_360box_mult_sys`.

Các dấu hiệu này phù hợp với việc phân loại driver này là driver chính sách sandbox/cô lập, không chỉ là một bộ lọc quét AV đơn giản.

## 6. Ghi chú HVM / bảo vệ memory

`360Hvm64.sys` import `MmMapIoSpace` và đăng ký các routine process/image notify. Chuỗi của driver chứa nhiều tên syscall process/thread:

```text
NtCreateProcess
NtCreateProcessEx
NtCreateUserProcess
NtCreateThread
NtCreateThreadEx
NtOpenThread
NtTerminateProcess
NtQueueApcThread
NtSetContextThread
NtOpenProcess
NtSuspendProcess
NtResumeProcess
NtAlpcOpenSenderThread
NtAlpcOpenSenderProcess
NtChangeProcessState
NtChangeThreadState
```

Driver cũng có các stub thông điệp thread liên quan win32k:

```text
__win32kstub_NtUserPostThreadMessage
__win32kstub_NtUserSetInformationThread
__win32kstub_NtUserAttachThreadInput
```

Bề mặt binary này nhất quán với các tuyên bố công khai rằng `360Hvm64` theo dõi những thao tác nhạy cảm liên quan memory/process/thread. Riêng dữ liệu export từ IDA **không** chứng minh một thiết kế EPT hook cụ thể; việc đó vẫn cần dịch ngược sâu hơn vào VMX/VM-exit.

## 7. ELAM

`360elam64.sys` được ký bởi Microsoft Windows Early Launch Anti-malware Publisher và chứa:

```text
IoRegisterBootDriverCallback
IoUnregisterBootDriverCallback
```

Đây là bằng chứng cục bộ trực tiếp rằng corpus có một boot driver ELAM thật. Điều này không chứng minh service user-mode nào của 360, nếu có, đang chạy PPL trên một bản cài cụ thể.

## 8. Cross-reference giữa các component sản phẩm

`360qpesv64.sys` tham chiếu các driver cùng họ:

```text
360FsFlt.sys
360netmon.sys
360boost64.sys
360reskit64.sys
360SelfProtection64.sys
360Box64.sys
360AntiHacker64.sys
360qpesv64.sys
```

Chỉ một phần các driver cùng họ này có mặt trong corpus cục bộ. Hãy giữ các tên còn thiếu như những component ứng viên để tìm trên một bản cài sản phẩm đầy đủ.

## 9. Bảng vai trò driver cho tài liệu sản phẩm

| Driver | Mô tả theo góc nhìn sản phẩm | Chi tiết có backing từ reverse |
|---|---|---|
| `360FsFlt.sys` | Bộ lọc chính cho file/self-protection | Minifilter + object callbacks + process/thread/image + registry callback + communication port |
| `360Box64.sys` | Sandbox/cô lập | Minifilter + object callbacks + chính sách registry/process + thao tác giống file virtualization |
| `360netmon.sys` | Giám sát mạng | WFP callout/filter cho stream/datagram/established flow |
| `360AntiAttack64.sys` | Bảo vệ tấn công mạng | WFP stream/flow/injection; PDB gợi ý nguồn gốc bảo vệ SMBv1/SQL |
| `360AntiHacker64.sys` | Lớp mạng anti-hacker | Quản lý WFP provider/filter/callout và process notify |
| `360AntiHijack64.sys` | Bảo vệ hijack/DNS/web | WFP transport/stream injection và đầu mối tĩnh `doh.360.cn` |
| `360AntiSteal64.sys` | Chống đánh cắp/bảo vệ dữ liệu | Minifilter + process notify + communication port của sản phẩm |
| `360Camera64.sys` | Bảo vệ camera | Helper device/process-context, chưa thấy bề mặt WFP/minifilter |
| `360Hvm64.sys` | Bảo vệ HVM/memory | Process/image notify + bảng tên syscall cho thao tác nhạy cảm process/thread + `MmMapIoSpace` |
| `360elam64.sys` | ELAM | Đăng ký boot-driver callback |
| `360qpesv64.sys` | Driver dịch vụ sự kiện/bảo vệ sản phẩm | Minifilter + callback process/image/registry; tham chiếu các driver 360 cùng họ |
| `360Sensor64.sys` | Helper sensor | Device driver nhỏ; vai trò chính xác vẫn chưa chốt |

## 10. Câu hỏi còn mở

- Hợp đồng IOCTL và tên device chính xác không được ghi trong tài liệu này. Chúng nên nằm trong một tác vụ RE phòng thủ riêng và không nên biến thành công thức trigger.
- Altitude minifilter chính xác là dữ liệu registry lúc cài đặt, không thể khôi phục đầy đủ chỉ từ chuỗi IDA tĩnh trong corpus này.
- `360Hvm64.sys` cần phân tích sâu hơn vào VMX/EPT trước khi kết luận chính xác cách nó thực thi bảo vệ memory.
- `360qpesv64.sys` nhiều khả năng thuộc một pipeline sự kiện/bảo vệ sản phẩm rộng hơn; client user-mode và giao thức message chính xác vẫn cần trace trong lab.
- `360Sensor64.sys` có quá ít bề mặt tĩnh trong lần phân tích này để gán vai trò chính sách một cách tự tin.

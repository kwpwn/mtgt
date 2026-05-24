# Astra64-RW / ASTRA64.sys Code Walkthrough

Source code analyzed:

- `Astra64-RW/src/main.rs`
- `Astra64-RW/src/astra.rs`
- `Astra64-RW/src/kernel.rs`
- `Astra64-RW/src/lpe.rs`
- `Astra64-RW/src/pe.rs`

Upstream: https://github.com/BlackSnufkin/BYOVD/tree/main/Astra64-RW

## Driver Role

`ASTRA64.sys` is not modeled in the PoC as a normal "kill process" BYOVD driver. It is treated as a low-level hardware bridge. The wrapper in `astra.rs` exposes two capabilities:

- MSR read through the driver's MSR IOCTL.
- Physical memory read/write through a driver-backed physical-memory mapping path.

That is why this PoC is much more complex than a normal BYOVD process killer. The driver does not directly say "terminate this PID" or "copy this token". It gives raw low-level primitives. The exploit has to build a higher-level kernel virtual memory abstraction on top.

## Module Structure

`main.rs` is only a launcher. It prints the intended target environment and calls `lpe::run_lpe()`.

`astra.rs` is the driver abstraction:

- Opens the user-mode device path.
- Issues the MSR read request.
- Maps physical pages.
- Implements page-sized physical read/write helpers.
- Works around a driver quirk where the returned mapped virtual address is truncated.

`kernel.rs` turns raw physical memory into kernel-aware helpers:

- Implements a 4-level x86-64 page-table walk.
- Provides `vread`, `vread_u32`, `vread_u64`, and `vwrite`.
- Finds a plausible kernel CR3.
- Walks backward from the syscall entry address to locate `ntoskrnl`.
- Detects `_EPROCESS` offsets by Windows build.
- Walks `ActiveProcessLinks` to find the System process and the current process.

`lpe.rs` is the exploit orchestration:

- Opens the driver.
- Reads `IA32_LSTAR`.
- Discovers CR3 and kernel base.
- Resolves kernel and Win32k symbols from on-disk images.
- Finds the shadow service table descriptor.
- Finds a Win32k indirect jump thunk.
- Locates System and caller `_EPROCESS`.
- Temporarily redirects a Win32k syscall path to perform a kernel `memmove`.
- Restores modified state.
- Verifies the token change.

## Why Physical Memory Translation Is Required

The driver exposes physical memory. Windows kernel exploitation usually reasons in virtual addresses:

- `ntoskrnl` base is a virtual address.
- `_EPROCESS` is referenced by virtual address.
- `_TOKEN` fast refs are virtual pointers.
- Win32k service tables and IAT slots are virtual addresses.

Because of that mismatch, `kernel.rs` has to implement `virt_to_phys()`. The function extracts the PML4, PDPT, PD and PT indexes from a virtual address, reads page-table entries through physical memory, handles 1 GiB and 2 MiB large pages, and returns the final physical address.

The reason this technique is used is reliability. Once the exploit can translate virtual addresses, every later stage can be written as if it had normal kernel virtual read/write. Without translation, it would need slow and fragile physical-memory scanning for every target object.

## Why CR3 Discovery Uses KUSER_SHARED_DATA

`find_cr3()` scans low physical memory for PML4 candidates, then validates them by checking whether they translate `KUSER_SHARED_DATA` correctly.

This is chosen because `KUSER_SHARED_DATA` has a stable virtual address and contains version fields that can be sanity checked. A random page table may look plausible, but if it translates `KUSER_SHARED_DATA` and the version field reads as expected, it is a much better candidate for the active kernel page-table root.

This avoids relying on privileged CPU instructions from user mode and avoids a hardcoded CR3 value.

## Why IA32_LSTAR Is Read

`lpe.rs` reads `IA32_LSTAR`, which points into the syscall entry path. It uses this as a kernel pointer sanity check and then as an anchor to locate `ntoskrnl`.

The code then walks backward page by page from the syscall entry address until it finds an `MZ`/`PE` header matching an AMD64 PE32+ kernel image whose `SizeOfImage` covers the original `LSTAR` address.

This is used because KASLR hides the kernel base. Reading `LSTAR` gives a kernel address without relying on user-mode APIs that may be restricted or monitored.

## Why the PoC Resolves Symbols from On-Disk Images

The code calls `load_image()` and `export_rva()` for `ntoskrnl.exe`, `win32u.dll`, and Win32k host modules.

The reason: the exploit needs symbol-relative offsets such as exported routines and syscall stubs, but the in-memory kernel module is randomized. Loading an on-disk image gives stable RVAs; adding those RVAs to the discovered kernel base gives runtime VAs.

This is a common exploit pattern:

1. Find randomized module base at runtime.
2. Resolve RVA from disk image.
3. Compute runtime VA as `base + rva`.

## Why Shadow SSDT Is Used

The exploit targets a Win32k syscall path, not a normal NT syscall path.

The code:

- Parses `win32u!NtUserSetWindowPos` to recover the service index.
- Locates `KeServiceDescriptorTableShadow`.
- Reads the Win32k service descriptor.
- Computes the shadow service table entry address.

Why this path:

- GUI syscalls dispatch through the shadow service table.
- `NtUserSetWindowPos` is easy to trigger from user mode once the thread is converted to a GUI thread.
- The exploit can temporarily redirect one service entry to a controlled existing gadget.

This is a controlled transition into kernel context without loading unsigned kernel code.

## Why a Win32k IAT Thunk Gadget Is Selected

`find_gadget()` scans the loaded Win32k host image for `jmp qword ptr [rip+disp32]` style thunks and picks one within the signed offset range needed by the shadow SSDT entry encoding.

The exploit needs a target that:

- Is inside an existing signed kernel image.
- Can be encoded as a valid shadow service table entry.
- Indirects through an IAT slot that the exploit can temporarily overwrite.

This is why the gadget search cares about distance from the shadow table base. The service table entry format stores a compact signed offset, so not every kernel address is encodable.

## Why `memmove` Is Used

The exploit does not try to run custom shellcode. Instead it redirects the syscall path so that the eventual kernel call lands on `nt!memmove` with arguments controlled through the syscall parameters.

This is used because:

- `memmove` is legitimate kernel code.
- HVCI/kCFG/CET make custom kernel code execution much harder.
- A single 8-byte copy is enough to copy the System process token fast-ref into the caller's `_EPROCESS.Token`.
- It reduces the amount of modified kernel state and can be restored quickly.

This is a data-only LPE outcome achieved through a short-lived control-flow redirection.

## Why the Exploit Restores State

`lpe.rs` saves the original shadow table entry and original IAT slot value. After triggering the syscall, it writes both originals back and verifies restoration.

This is important because:

- Persistent SSDT or IAT tampering is PatchGuard-adjacent.
- Leaving a service table entry redirected can crash later unrelated GUI calls.
- Restore reduces the detection window and improves system stability.

## Why Token Fast-Ref Masking Matters

The code compares token values using `EX_FAST_REF_MASK`. `_EPROCESS.Token` is not a plain pointer; it is an `_EX_FAST_REF` where low bits store reference metadata.

The exploit copies the full fast-ref value, but verification masks low bits before comparing pointer identity. Without this, a successful token transfer can look different because of reference bits.

## Main Failure Points

- CR3 candidate discovery fails on a different memory layout.
- `KUSER_SHARED_DATA` validation changes or is unreadable through the mapping.
- `ntoskrnl` walkback fails due to page translation or header validation issues.
- `_EPROCESS` offsets do not match the running build.
- Win32k service descriptor pattern changes.
- The chosen gadget is not valid under a given build's kCFG/CET behavior.
- Restore fails, leaving corrupted kernel dispatch state.

## Why This Technique Was Chosen

The driver provides raw physical memory access, not a convenient high-level primitive. The exploit therefore builds:

1. Physical R/W.
2. Virtual-to-physical translation.
3. Kernel virtual R/W.
4. Dynamic symbol/module discovery.
5. Short-lived legitimate-kernel-code copy primitive.
6. Data-only token transfer.

This is the natural chain for a modern physical-memory BYOVD target under HVCI/VBS: avoid unsigned code, avoid permanent patching, use legitimate kernel code briefly, and restore state.

## Defensive Takeaways

- HVCI-compatible does not mean safe if a signed driver exposes physical memory.
- Block by driver hash/signature/product, not just filename.
- Monitor driver load followed by token anomaly or unexpected SYSTEM child process.
- Service-table/IAT modifications are high-signal but hard to observe without kernel telemetry.
- Preventing driver load is more reliable than detecting the final token transfer.

## Engineering Decision Analysis

This section explains the exploit writer's likely reasoning: why this chain is structured this way, what alternatives exist, and how stable each choice is.

### Decision 1: Use physical-memory R/W instead of trying to abuse MSR write

Chosen path:

- Use the driver mapping primitive to build physical read/write.
- Convert that into virtual kernel read/write through page-table walking.
- Use kernel virtual R/W to modify a very small amount of state.

Alternative:

- Use MSR write, especially syscall-entry related MSRs, to redirect execution.

Why the chosen path is better:

- Physical-memory R/W is a general primitive. Once virtual translation works, it can support many target objects.
- MSR write is high-impact but brittle. A wrong value or unexpected syscall path can crash immediately.
- MSR hijack affects global CPU/kernel behavior, while physical R/W can be scoped to specific addresses.
- HVCI/kCFG/CET make arbitrary control-flow redirection less attractive than data-only outcomes.

Stability:

- Physical R/W itself is stable if the mapping IOCTL works.
- The virtual-to-physical bridge is moderately version-stable because x86-64 paging rules are architectural.
- The target offsets and later dispatch hijack are version-sensitive.

BSOD risk:

- MSR write path: high.
- Physical read path: low to medium if invalid pages are handled safely.
- Physical write path: medium to high depending on target.

### Decision 2: Page-table walk instead of blind physical memory scanning

Chosen path:

- Discover a CR3 candidate.
- Walk page tables to translate known kernel virtual addresses.

Alternative:

- Scan physical memory for `_EPROCESS`, PE headers, pool tags or token-like structures.

Why the chosen path is better:

- Page walking is deterministic after CR3 discovery.
- It reduces false positives.
- It makes later code cleaner: most exploit logic can operate on kernel virtual addresses.
- It is faster and less destructive than scanning then guessing.

Why not always use it:

- You need a valid page-table root.
- Some protected or unusual memory regions may fault or translate differently under VBS/hypervisor constraints.
- Kernel virtual address targets still need to be discovered first.

Stability:

- Paging format is stable across Windows versions on x64.
- CR3 discovery logic is less stable because it relies on heuristics.
- KUSER_SHARED_DATA validation is a good anchor, but still an implementation choice.

BSOD risk:

- Reads during page walk are relatively safe if failures are handled.
- Writing to translated addresses is only safe if the target virtual address is correct.

### Decision 3: Use `KUSER_SHARED_DATA` to validate CR3

Chosen path:

- Scan low physical memory for plausible PML4 roots.
- Translate `KUSER_SHARED_DATA`.
- Validate a known version field.

Alternatives:

- Use a kernel debugger/symbols to obtain CR3. Not available in real exploit.
- Scan for process structures and infer directory table base.
- Use a leak from another kernel object.

Why the chosen path is good:

- `KUSER_SHARED_DATA` has a stable virtual address.
- The content has predictable fields.
- It avoids requiring an existing virtual read primitive.

Weakness:

- The scan range and candidate heuristics are assumptions.
- Different virtualization or memory layouts can move relevant tables outside expected ranges.
- It may find a valid-looking but wrong address space if validation is weak.

Stability:

- Good conceptually across many Windows x64 builds.
- Implementation-specific scan limits may need adjustment.

BSOD risk:

- Low, mostly read-only probing.

### Decision 4: Use `IA32_LSTAR` to find `ntoskrnl`

Chosen path:

- Read `IA32_LSTAR`.
- Treat it as a pointer into `ntoskrnl` syscall entry.
- Walk backward by pages to find an `MZ`/`PE` header.

Alternatives:

- Use `NtQuerySystemInformation(SystemModuleInformation)` from user mode.
- Use hardcoded kernel base assumptions.
- Search all translated kernel memory for `MZ`.
- Leak kernel base through handle/object APIs.

Why the chosen path is good:

- `LSTAR` directly reveals a kernel pointer.
- It is independent of user-mode API restrictions.
- It avoids broad memory scanning.
- It is robust when the driver already exposes MSR read.

Weakness:

- Requires MSR read support.
- Assumes `LSTAR` points inside the main kernel image and not through unexpected instrumentation.
- The walkback validation must be correct or it can misidentify a module.

Stability:

- Generally stable on x64 Windows because syscall entry is kernel-resident.
- More stable than hardcoded KASLR bypasses.

BSOD risk:

- Very low for read-only MSR and memory reads.

### Decision 5: Resolve exports from on-disk images

Chosen path:

- Load disk images for export RVAs.
- Add RVAs to discovered runtime bases.

Alternatives:

- Parse in-memory PE export directory with virtual reads.
- Use PDB symbols.
- Hardcode offsets.
- Pattern scan memory.

Why the chosen path is good:

- Export RVAs are stable for a given binary.
- Disk parsing is easier and safer than in-memory export parsing through a fragile primitive.
- Avoids symbol server dependency.
- Avoids hardcoded offsets for exported functions.

Weakness:

- Disk image must match the loaded kernel module.
- Some modules can be patched or have different file versions.
- Not useful for non-exported internals.

Stability:

- Good across builds if image matching is correct.
- Export names can disappear, but common exports like `memmove` and `PsInitialSystemProcess` are usually available in target ranges.

BSOD risk:

- None for disk parsing.
- Runtime use of wrong RVA can cause crash later.

### Decision 6: Use shadow SSDT / Win32k path instead of normal SSDT

Chosen path:

- Hijack one Win32k syscall entry, `NtUserSetWindowPos`.

Alternatives:

- Patch normal SSDT.
- Patch a function pointer inside a kernel object.
- Patch an IAT slot only and call through an existing path.
- Directly write token field with virtual write.

Why this path is attractive:

- Win32k syscalls give user-controlled parameters through a known syscall stub.
- The shadow table entry encoding is compact but usable if a nearby gadget exists.
- A GUI syscall can be triggered from the current process after converting the thread.
- It avoids creating executable memory or injecting a driver.

Why not direct token write:

- The code has `vwrite`, so direct token write would be simpler.
- But the author appears to demonstrate kernel-context copy through a syscall redirection, possibly to avoid VTL/HVCI edge cases or to show a more general kernel write primitive.
- Direct physical/virtual write into `_EPROCESS.Token` may be enough on many systems, but can run into protected/EPT behavior or cache/coherency assumptions depending on mapping.

Why not normal SSDT:

- Normal SSDT patching is heavily scrutinized historically.
- A suitable target/gadget may be easier in Win32k host modules.
- GUI syscall stubs are convenient for parameter shaping.

Stability:

- Medium to low across Windows versions.
- Win32k internals, service indexes and table descriptor patterns change more often than paging mechanics.
- Windows 11 24H2/25H2 changes can break pattern scans or gadget selection.

BSOD risk:

- Medium to high.
- Any wrong entry encoding, bad gadget, bad IAT pointer or failed restore can crash immediately or later.

### Decision 7: Use an existing `jmp [rip+disp32]` thunk plus IAT slot patch

Chosen path:

- Find a Win32k indirect jump thunk near the shadow table base.
- Patch its IAT slot to `nt!memmove`.
- Encode the service table entry to point at the thunk.

Alternatives:

- Encode service entry directly to `memmove`.
- Place custom shellcode and point service entry at it.
- Use an existing function that already has desired behavior.

Why the chosen path is needed:

- Shadow SSDT entries encode signed relative offsets with limited range.
- `nt!memmove` may not be within encodable range from the Win32k service table base.
- A nearby Win32k thunk is encodable, and its IAT slot can redirect to the far target.

Why not shellcode:

- HVCI and NX make unsigned executable kernel payloads harder.
- Allocating executable kernel memory is noisy and often blocked.
- kCFG/CET can complicate indirect control flow to arbitrary code.

Stability:

- Gadget availability is version-dependent.
- The generic thunk pattern is common, but exact location and IAT mutability vary.

BSOD risk:

- Medium.
- Wrong thunk or IAT slot can jump to invalid code.
- Concurrent calls during the patch window can hit redirected behavior.

### Decision 8: Use `memmove` for token copy

Chosen path:

- Redirect syscall to `nt!memmove`.
- Pass destination as current process token field, source as System token field, size as 8.

Alternatives:

- Use direct `vwrite` to write the token value.
- Use `RtlCopyMemory` or another copy routine.
- Build a more general arbitrary kernel call primitive.
- Modify privileges inside `_TOKEN` instead of copying token fast-ref.

Why `memmove` is good:

- It is exported/resolvable.
- It is legitimate kernel code.
- It has a simple calling convention.
- It handles overlapping memory, though overlap does not matter here.
- It performs exactly the one operation needed: copy 8 bytes.

Why not privilege-bit modification:

- Token internals are more complex and version-sensitive.
- Copying the System token fast-ref is a classic compact LPE.
- Modifying only privileges might not give the same practical access as a full SYSTEM primary token.

Stability:

- Token offset is version-sensitive.
- `memmove` export and calling convention are stable enough.
- Token copy is conceptually stable but increasingly monitored.

BSOD risk:

- Low if addresses are correct.
- High if offsets are wrong or destination points into invalid/corrupt memory.

### Decision 9: Restore immediately

Chosen path:

- Patch only during the trigger window.
- Restore shadow table entry and IAT slot immediately.
- Verify restoration.

Alternatives:

- Leave hook in place.
- Install a persistent kernel payload.
- Patch another long-lived callback/list.

Why restore is essential:

- PatchGuard and security products look for persistent kernel tampering.
- A hijacked GUI syscall can crash unrelated GUI activity.
- Short-lived patching reduces stability and detection risk.

Stability:

- Restoration improves stability but does not eliminate race conditions.
- If another thread invokes the same service while patched, behavior is unpredictable.

BSOD risk:

- Lower than persistent patching.
- Still non-trivial during the patch window.

### Version Stability Summary

| Component | Stability across Windows builds | Reason |
|---|---|---|
| Physical memory IOCTL | Driver-version dependent | If IOCTL semantics change, whole primitive changes. |
| x64 page-table walk | High | Architectural, not Windows-specific. |
| CR3 heuristic | Medium | Scan range and validation assumptions can break. |
| LSTAR kernel-base anchor | High if MSR read works | Syscall entry remains kernel-resident. |
| Export RVA resolution | Medium-high | Requires disk image match; exports may change. |
| `_EPROCESS` offsets | Low-medium | Build-sensitive; 24H2 changed offsets significantly. |
| Shadow SSDT descriptor scan | Low-medium | Pattern and structure-sensitive. |
| Win32k thunk selection | Low-medium | Module layout and CFG/CET behavior change. |
| Token fast-ref copy | Medium | Concept stable; offset and detection vary. |

### BSOD Risk Summary

| Stage | Risk | Why |
|---|---|---|
| Open driver / read MSR | Low | Read-only and simple API use. |
| Physical read mapping | Low-medium | Bad mappings can fault; code uses safer copy path. |
| Page-table walk | Low | Mostly reads and validates present bits. |
| Virtual write | Medium | Any wrong translation corrupts memory. |
| Shadow SSDT patch | High | Global dispatch state is sensitive. |
| IAT slot patch | Medium-high | Wrong slot affects indirect control flow. |
| Syscall trigger | Medium-high | Arguments must match called routine expectations. |
| Restore | Medium | Failure leaves system unstable. |

### Reliability Improvements Worth Considering

- Use symbols or PDB-derived offsets instead of build-range hardcoding.
- Pin or suspend competing GUI activity during the patch window in a lab setting.
- Validate gadget target and IAT slot by reading original pointer and checking it points into expected module range.
- Add build allowlist rather than broad build ranges.
- Add crash-safe logging for every address selected.
- Prefer direct data-only virtual write when the driver/mapping behavior allows it reliably.
- Add a dry-run mode that resolves all addresses and validates page translations without writing.

# ASTRA64 Direct DKOM Token Swap Deep Dive

This document explains the direct-token-write approach for `ASTRA64.sys` concept by concept. It compares the design with the BlackSnufkin Astra64-RW chain and explains why each technique exists, what it buys, what it breaks on, and where BSOD risk comes from.

The code pattern discussed here is:

```text
ASTRA64 physical memory map
  -> MSR LSTAR leak
  -> CR3 discovery
  -> x64 page-table walk
  -> kernel VA read/write abstraction
  -> locate System and current EPROCESS
  -> translate EPROCESS.Token VAs to physical addresses
  -> direct physical write of System token fast-ref into current EPROCESS
  -> spawn child process
  -> restore original token
```

It deliberately avoids:

- Shadow SSDT patching.
- Win32k service table redirection.
- IAT thunk patching.
- Kernel shellcode.
- Long-lived kernel hooks.

## 1. What `ASTRA64.sys` Gives You

`ASTRA64.sys` is valuable because it exposes hardware-style primitives to user mode. The key one is a physical memory mapping IOCTL.

Conceptually:

```text
user supplies physical address + size
driver maps that physical range into caller's user VA
caller reads/writes the mapped user VA
changes affect the underlying physical page
```

This is not the same as a normal arbitrary kernel virtual write.

With a virtual write primitive, the caller says:

```text
write 8 bytes to kernel virtual address FFFF...
```

With ASTRA64's physical mapping primitive, the caller must say:

```text
map physical page 12345000
write at mapped user address + offset
```

That distinction drives almost every technique in the exploit. The target object is known by virtual address, but the driver operates on physical address.

## 2. Why Physical Memory R/W Is Powerful

Physical memory R/W is powerful because it sits below many normal kernel abstractions:

- It does not require the driver to dereference a kernel virtual address.
- It can read/write memory that belongs to `ntoskrnl`, pool, process objects, page tables, device mappings and other kernel data.
- Once you can translate kernel VA to PA, it becomes a general kernel virtual R/W primitive.
- It can avoid some API-level checks because the driver maps the backing page directly.

But it is not magic:

- It does not automatically understand Windows objects.
- It does not know which physical page contains `_EPROCESS`.
- It does not bypass every VBS/VTL1/KDP protection.
- It can crash or corrupt the system if the wrong page is written.

Physical R/W is a strong low-level primitive, not a complete exploit by itself.

## 3. Physical Address vs Kernel Virtual Address

Windows kernel code normally uses virtual addresses. `_EPROCESS`, `_TOKEN`, service tables and kernel images are referenced as canonical kernel virtual addresses such as:

```text
FFFF... 
```

The CPU translates those virtual addresses through page tables to physical memory.

ASTRA64 maps physical pages. Therefore, if the exploit wants to read:

```text
EPROCESS.Token at kernel VA X
```

it must first compute:

```text
physical address backing virtual address X
```

That is the VA->PA problem.

There are two broad ways to solve it:

1. Blind physical scanning.
2. Page-table walking.

The code chooses page-table walking.

## 4. Why Page-Table Walking Instead of Blind Physical Scanning

Blind physical scanning means searching RAM for recognizable structures:

- PE headers.
- `_EPROCESS.ImageFileName`.
- PID values.
- linked-list patterns.
- token-looking pointers.

It can work, but it is fragile:

- False positives are common.
- It is slow.
- It can miss objects.
- It becomes dangerous when a scan result is used as a write target.
- It is affected by memory pressure, VM layout, hibernation, crash dump state and Windows version.

Page-table walking is more deterministic:

```text
given CR3 and VA
read PML4E
read PDPTE
read PDE
read PTE
combine PFN with page offset
return physical address
```

Why it is better:

- x64 paging format is architectural.
- Once CR3 is correct, translation is direct.
- It allows the rest of the exploit to think in kernel virtual addresses.
- It reduces the chance of writing to the wrong object.

What it costs:

- You need a valid CR3/page-table root.
- You need to handle large pages.
- You must handle translation failures cleanly.
- HVCI/VBS can complicate access to some regions, though normal VTL0 kernel objects are usually still reachable.

## 5. What CR3 Means Here

CR3 is the CPU register that points to the top-level page table. On x64 with 4-level paging:

```text
CR3 -> PML4 -> PDPT -> PD -> PT -> physical page
```

The exploit cannot read CR3 directly from user mode. So it must infer a page-table root from physical memory.

Important detail: Windows uses shared kernel mappings. Kernel global memory such as nonpaged pool and `_EPROCESS` can be translated using a suitable system/kernel page-table context. The code assumes the discovered CR3 maps the kernel global region correctly.

This is why the comment says:

```text
EPROCESS is non-paged global kernel memory -> accessible via system CR3
```

That is broadly correct for the target object class, but still an assumption that should be validated by reads before writes.

## 6. Why `KUSER_SHARED_DATA` Is Used to Find CR3

`KUSER_SHARED_DATA` has a well-known virtual address:

```text
0xFFFFF78000000000
```

It contains stable fields such as Windows version information. The exploit scans low physical memory for pages that look like PML4 pages and tests whether they translate this address correctly.

The validation is:

```text
candidate PML4 -> translate KUSER_SHARED_DATA
read NtMajorVersion-like field
expect 10
```

Why this is a good heuristic:

- The virtual address is stable.
- The data is easy to validate.
- It only requires reads.
- It avoids depending on a debugger or symbol server.

Weakness:

- It is still a heuristic.
- Scan range assumptions may fail.
- Multiple candidates could pass weak validation.
- Offset `0x26C` is an implementation detail.

BSOD risk:

- Low, because this stage only reads.
- The bigger risk is accepting the wrong CR3, then using it for later writes.

## 7. How the Page-Table Walk Works

For a canonical x64 virtual address:

```text
bits 47..39 = PML4 index
bits 38..30 = PDPT index
bits 29..21 = PD index
bits 20..12 = PT index
bits 11..0  = page offset
```

The code reads:

```text
PML4E = phys_read(CR3 + pml4_index * 8)
PDPTE = phys_read((PML4E.PFN << 12) + pdpt_index * 8)
PDE   = phys_read((PDPTE.PFN << 12) + pd_index * 8)
PTE   = phys_read((PDE.PFN << 12) + pt_index * 8)
PA    = (PTE.PFN << 12) + page_offset
```

It also handles large pages:

- PDPTE large page bit -> 1 GiB page.
- PDE large page bit -> 2 MiB page.

Why large-page handling matters:

- Kernel images and some mappings can use large pages depending on build/config.
- If the walker ignores large pages, translation fails or returns wrong PA.

Stability:

- The paging bit layout is stable on x64.
- The masks must be correct.
- LA57/5-level paging would require different logic, but normal Windows desktop targets are typically 4-level in this context.

BSOD risk:

- Reading page-table entries is low risk.
- Writing through a PA returned by a bad walk is high risk.

## 8. Why MSR `IA32_LSTAR` Is Read

`IA32_LSTAR` holds the target address for the `syscall` instruction in long mode. On Windows, it points into the kernel syscall entry path, typically inside `ntoskrnl`.

The exploit reads it through ASTRA64's MSR read IOCTL.

Why it is used:

- It is a reliable kernel pointer leak.
- It bypasses KASLR for the main kernel image.
- It avoids `NtQuerySystemInformation(SystemModuleInformation)` restrictions.
- It gives a starting point for finding `ntoskrnl` base.

Why not use MSR write:

- MSR write is much more dangerous.
- Redirecting syscall entry can crash instantly.
- Modern mitigations make control-flow hijack less attractive.
- Direct token write only needs read access to LSTAR, not write access.

Stability:

- Good if the driver exposes MSR read.
- `LSTAR` being inside the syscall path is a stable x64 Windows property.

BSOD risk:

- MSR read is low risk.
- MSR write would be high risk.

## 9. How Kernel Base Is Found

The code walks backward from `LSTAR` page by page:

```text
current = page_align(LSTAR)
while current looks like kernel pointer:
    read 0x200 bytes at current
    check MZ
    check PE
    check AMD64 machine
    check PE32+ optional header
    check SizeOfImage covers LSTAR
```

Why this works:

- PE images start with `MZ`.
- Kernel text containing `LSTAR` lives inside `ntoskrnl`.
- Walking backward from a known inside pointer eventually reaches image base.

Why validate `SizeOfImage`:

- Random memory can contain `MZ`.
- The image must be large enough and must contain the original `LSTAR` pointer.
- This avoids false positives.

Alternative:

- Use `SystemModuleInformation`.
- Parse kernel loaded module list.
- Hardcode base.
- Scan all kernel memory for PE headers.

Chosen approach is good because it uses the MSR leak already available and stays self-contained.

## 10. Why Load `ntoskrnl.exe` from Disk

The exploit needs the address of `PsInitialSystemProcess`.

At runtime:

```text
runtime VA = runtime nt base + export RVA
```

The disk image gives the export RVA. KASLR only changes the base, not the RVA inside the same binary.

Why not hardcode `PsInitialSystemProcess` offset:

- It changes by build.
- Disk export parsing is more stable.

Why not parse the in-memory export directory:

- That would require more kernel reads.
- Disk parsing is simpler and safer.

Weakness:

- Disk image must match the loaded kernel.
- If the file is different from the loaded image, RVA may be wrong.

## 11. Why `PsInitialSystemProcess` Is the Entry Point

`PsInitialSystemProcess` is an exported kernel variable pointing to the System process `_EPROCESS`.

Why this is useful:

- System PID is always 4.
- System token is the classic token to copy.
- From System `_EPROCESS`, you can walk `ActiveProcessLinks` to find other processes.

The exploit reads:

```text
*(ntoskrnl_base + RVA(PsInitialSystemProcess))
```

and validates:

```text
SystemEPROCESS.UniqueProcessId == 4
```

This validation is important. Without it, a wrong kernel base or wrong RVA could produce a bogus pointer, and the later write would corrupt memory.

## 12. `_EPROCESS` Fields Used

The exploit uses only three offsets:

- `UniqueProcessId`
- `ActiveProcessLinks`
- `Token`

`UniqueProcessId` identifies the process.

`ActiveProcessLinks` links all active processes in a doubly-linked list.

`Token` is an `_EX_FAST_REF` to the process token.

This minimal offset set is good because every additional structure offset increases version fragility.

The weak part is hardcoding only two offset families:

```text
build >= 26100 -> 24H2/Server 2025 style offsets
else           -> 19041..26099 style offsets
```

That is fine for a narrow lab range, but it is not universal.

## 13. Why `ActiveProcessLinks` Walk Works

Every normal process is linked into `PsActiveProcessHead` through `_EPROCESS.ActiveProcessLinks`.

The code starts from System `_EPROCESS`, gets the process list head from the `Blink` of System's list entry, then walks forward through `Flink`.

For each list entry:

```text
EPROCESS = Flink - ActiveProcessLinksOffset
PID = *(EPROCESS + UniqueProcessIdOffset)
```

When PID matches the current process, it has the target `_EPROCESS`.

Why this is used:

- No need for handle leaks.
- No need for `PsLookupProcessByProcessId`.
- It works with pure read primitive.

Weakness:

- List corruption or hidden processes can break it.
- Offset mismatch breaks it.
- Protected/isolated process edge cases may require different handling.

BSOD risk:

- The walk itself only reads, so low risk.
- Acting on a wrong result is high risk.

## 14. What `_EX_FAST_REF` Means for Token

`_EPROCESS.Token` is not just a raw pointer. It is an `_EX_FAST_REF`.

On x64, low bits are used for reference metadata. The pointer is obtained by masking low bits:

```text
token_pointer = token_value & ~0xF
```

The exploit copies the full 8-byte fast-ref from System to current process.

Why copy the full fast-ref:

- It is simple.
- It preserves the low reference bits from System's token fast-ref.
- It is the classic DKOM token swap technique.

Why verification masks low bits:

- Two token fast-ref values can differ in low ref bits while pointing to the same token.
- Comparing pointer identity requires masking low bits.

Reference-count caveat:

- This is not a clean object-manager reference transfer.
- It can temporarily make reference accounting inconsistent.
- Restoring the original token reduces long-term damage.

## 15. Direct DKOM Token Swap

DKOM means Direct Kernel Object Manipulation.

Here the object is current process `_EPROCESS`:

```text
current_eprocess.Token = system_eprocess.Token
```

The code does this at physical address level:

1. Translate `system_eprocess + TokenOffset` to physical address.
2. Translate `current_eprocess + TokenOffset` to physical address.
3. Read 8-byte System token fast-ref.
4. Read and save 8-byte original current token fast-ref.
5. Write System token fast-ref to current token field.
6. Spawn child process.
7. Restore original token fast-ref.

Why this works:

- Access checks use the process token.
- After swap, the current process appears to hold SYSTEM's token.
- A child process can inherit that elevated security context.

Why it is powerful:

- It needs one 8-byte write.
- No shellcode.
- No control-flow hijack.
- No SSDT patch.
- No callback tamper.

Why it is dirty:

- It mutates kernel object state without object-manager APIs.
- It does not acquire locks.
- It does not update references cleanly.
- It is visible to security telemetry if monitored.

## 16. Why Direct Write Instead of BlackSnufkin's `memmove` Route

BlackSnufkin's route:

```text
patch Win32k shadow SSDT entry
patch IAT slot to nt!memmove
trigger NtUserSetWindowPos(dst, src, 8)
restore SSDT/IAT
```

Your route:

```text
write 8 bytes directly to physical address backing current_eprocess.Token
```

Direct write is better if:

- Physical write is reliable.
- Target field is in normal VTL0 nonpaged kernel memory.
- You only need a simple data-only LPE.
- You want fewer moving parts.

`memmove` route is better if:

- Direct user mapping writes fault or behave inconsistently under HVCI/EPT.
- You want the copy performed by legitimate kernel code.
- You are demonstrating a more general kernel-call primitive.
- You want to avoid raw writes into certain mapped pages.

For ASTRA64 token swap specifically, direct write is more pragmatic.

It removes:

- Win32k pattern scan.
- Shadow service descriptor discovery.
- Service index parsing.
- Thunk search.
- IAT patch.
- Global syscall dispatch race.
- Need to restore service table state.

## 17. Why Direct Write Is Usually More Stable Here

The direct route depends on:

- Driver physical mapping works.
- CR3 is correct.
- Page-table walk is correct.
- EPROCESS offsets are correct.
- Token field is writable physical memory.

The BlackSnufkin route depends on all of the above plus:

- Win32k host module discovery.
- Shadow SSDT descriptor pattern.
- Service index layout.
- Encodable thunk within relative offset range.
- IAT slot mutability.
- Correct syscall argument mapping to `memmove`.
- Race-free patch and restore.

Fewer dependencies usually means better stability.

## 18. Where Direct Write Can Still Fail

Direct DKOM can fail in several ways:

Wrong offsets:

- You write into the wrong `_EPROCESS` field.
- This can corrupt a pointer, list entry or flag.

Wrong CR3:

- Virtual-to-physical translation returns wrong PA.
- Write corrupts unrelated physical memory.

Wrong process:

- EPROCESS walk finds wrong PID or stale object.
- You elevate the wrong process or corrupt another process.

Protected memory:

- Target page is protected by hypervisor/KDP-like mechanism.
- Write may fault, be ignored, or crash.

Reference issues:

- Token reference count metadata is not updated cleanly.
- Long-lived swapped token can produce object lifetime weirdness.

Restore failure:

- If process crashes before restore, token remains swapped.
- If target physical address changes or translation fails during restore, original token is not restored.

## 19. HVCI/VBS Boundary Reality

Physical memory R/W is often described as "bypassing HVCI". More precise wording:

```text
It bypasses many HVCI-era code-execution assumptions,
but it does not bypass every VBS/VTL1 memory protection.
```

HVCI mainly raises the cost of:

- unsigned kernel code,
- writable+executable memory,
- patching executable code,
- loading incompatible drivers.

Your direct DKOM route does not need kernel code execution. It changes data.

That is why it can still work under HVCI when the vulnerable signed driver is allowed to load.

But VBS can still protect some regions:

- Secure kernel memory.
- VTL1 trustlets.
- KDP-protected data.
- Secure pool allocations.
- Hypervisor-protected code/data pages.

`_EPROCESS.Token` in normal VTL0 kernel memory is generally not in those protected regions, which is why token DKOM remains viable in this model.

## 20. BSOD Risk: Direct Route

| Stage | BSOD risk | Reason |
|---|---|---|
| Open ASTRA device | Low | User-mode handle open fails cleanly. |
| Read MSR LSTAR | Low | Read-only operation. |
| Scan CR3 candidates | Low | Read-only physical probing. |
| Page-table walk | Low | Reads only, if failures handled. |
| Find kernel base | Low | Reads only. |
| EPROCESS walk | Low | Reads only. |
| Translate token VA | Medium | Wrong CR3/offset can produce wrong PA. |
| Read token fields | Low-medium | Bad PA can fault through mapping. |
| Write token field | High | Any wrong PA corrupts kernel memory. |
| Spawn child process | Low | Normal user-mode API after token swap. |
| Restore token | Medium-high | Restore write must target same correct field. |

The highest-risk operation is the 8-byte physical write. The exploit's reliability is mostly about making sure that one address is correct.

## 21. BSOD Risk: BlackSnufkin Route

| Stage | BSOD risk | Reason |
|---|---|---|
| All discovery stages | Same as direct route | Same physical/virtual setup. |
| Find shadow SSDT | Medium | Pattern mismatch can select wrong table. |
| Patch service entry | High | Global dispatch corruption. |
| Patch IAT slot | Medium-high | Wrong slot redirects unrelated code. |
| Trigger syscall | High | Bad calling convention/arguments crash. |
| Concurrent syscall race | Medium-high | Other threads can hit patched entry. |
| Restore | Medium-high | Failed restore leaves global corruption. |

This route has a larger BSOD surface, but it demonstrates a more advanced kernel-context call technique.

## 22. Version Stability Comparison

| Technique | Direct DKOM route | Shadow SSDT route |
|---|---|---|
| ASTRA IOCTL | Same dependency | Same dependency |
| CR3 discovery | Same dependency | Same dependency |
| Page-table walk | Same dependency | Same dependency |
| `ntoskrnl` base | Same dependency | Same dependency |
| `_EPROCESS` offsets | Required | Required |
| Win32k internals | Not required | Required |
| Shadow SSDT layout | Not required | Required |
| Service index parsing | Not required | Required |
| Thunk availability | Not required | Required |
| IAT slot mutability | Not required | Required |
| Race-free restore | Only token restore | SSDT + IAT restore |

Direct DKOM is more stable across Windows versions because it touches fewer version-sensitive internals.

The remaining version-sensitive piece is `_EPROCESS`.

## 23. Offset Strategy

The code uses:

```text
if build >= 26100:
    pid   = 0x1D0
    links = 0x1D8
    token = 0x248
else:
    pid   = 0x440
    links = 0x448
    token = 0x4B8
```

This covers the intended Windows 10 2004+ to Windows 11 23H2 family and Windows 11 24H2+ family at a high level.

Limitations:

- It does not support older builds like 17763, 18362, 14393.
- Future builds can change layout.
- Insider builds can diverge.
- Server SKUs can differ.

Better strategies:

- Query exact offsets from PDB symbols.
- Maintain a build-to-offset table generated from Vergilius/PDBs.
- Add runtime validation:
  - PID field equals expected PID.
  - `ImageFileName` matches.
  - `Token & ~0xF` is a kernel pointer.
  - `ActiveProcessLinks` pointers are canonical and circular.

## 24. Why `EPROCESS` Is a Good DKOM Target

`_EPROCESS` is attractive because:

- It is nonpaged.
- It is globally reachable.
- It contains process identity and token state.
- It is linked into a discoverable process list.
- Token swap requires only one pointer-sized write.

Why not modify `_TOKEN` privileges instead:

- `_TOKEN` layout is more complex.
- Privilege structures have multiple bitmaps/fields.
- Enabling privileges may not give full SYSTEM identity.
- Token copy is shorter and easier to verify.

Why not modify PPL fields:

- PPL fields are useful for security-product bypass, but not always enough for LPE.
- They are more likely to be monitored.
- Token swap gives immediate broad access.

## 25. Why Restore Original Token

Restoring is good engineering:

- Reduces reference-count/lifetime side effects.
- Reduces forensic exposure.
- Avoids leaving the original process permanently SYSTEM.
- Makes repeated lab runs cleaner.

But restore after spawning shell has a subtle point:

- The child process must inherit or receive the elevated token before restore.
- If the parent restores too early, child may not get SYSTEM.
- If the parent waits too long, the window of elevated parent token is larger.

The code waits briefly after process creation. That is a pragmatic lab choice, not a perfect synchronization model.

More robust verification would check the child process token identity rather than only parent token elevation.

## 26. Why `TokenElevation` Is Not Sufficient Verification

`TokenElevation` answers whether the token is elevated under UAC semantics. It does not prove the token is SYSTEM.

Better verification:

- Query token user SID.
- Check for `S-1-5-18` LocalSystem.
- Check process owner.
- Compare masked token pointer against System token pointer.

Your code already does the most relevant kernel-level verification:

```text
(new_token & ~0xF) == (system_token & ~0xF)
```

That proves the process token fast-ref points to the same token object, ignoring fast-ref low bits.

## 27. Detection and Telemetry View

Direct DKOM route avoids noisy SSDT/IAT patching, but it still has detectable behaviors:

- Loading or opening `ASTRA64.sys`.
- Opening `\\.\Astra32Device0`.
- MSR read IOCTL use.
- Physical memory mapping IOCTL use.
- Sudden token anomaly in current process.
- SYSTEM child process from unexpected parent.
- Driver service creation from user-writable path.

Defenders usually cannot see every IOCTL by default. Therefore, the most realistic detections are:

- Driver load.
- Service creation.
- File hash/signature.
- Process tree anomaly.
- Security process tamper.
- WDAC/blocklist deny events.

## 28. Direct Route vs Shadow Route: Practical Verdict

For learning advanced exploitation:

- BlackSnufkin route teaches Win32k/shadow SSDT dispatch, thunk selection and kernel-context function call.

For a practical ASTRA64 token swap:

- Direct DKOM is cleaner.
- It is shorter.
- It has fewer version-sensitive dependencies.
- It has less global kernel tamper.
- It is less likely to crash due to dispatch races.

The direct route is the better engineering choice if:

- The target is `_EPROCESS.Token`.
- Physical write works reliably.
- You do not need a general kernel call primitive.

The shadow route is interesting if:

- Direct physical write is unreliable on the target.
- You want to perform an operation through kernel code.
- You are studying syscall dispatch and kCFG-era constraints.

## 29. Reliability Checklist for Direct DKOM

Before writing:

- Confirm driver hash/version.
- Confirm device open path.
- Confirm MSR read returns canonical kernel pointer.
- Confirm CR3 validates `KUSER_SHARED_DATA`.
- Confirm `ntoskrnl` base has valid PE header and covers LSTAR.
- Confirm `PsInitialSystemProcess` points to PID 4.
- Confirm current PID is found in process list.
- Confirm token values are canonical after masking low bits.
- Confirm both token field VAs translate to physical addresses.
- Re-read token fields immediately before write.

After writing:

- Re-read current token field.
- Compare masked token pointer to System token pointer.
- Spawn child process.
- Verify child identity if possible.
- Restore original token.
- Re-read and confirm original token restored.

## 30. Summary

The ASTRA64 direct DKOM chain is powerful because it uses the shortest path from physical memory primitive to LPE:

```text
physical R/W -> VA/PA bridge -> locate process objects -> one 8-byte token write
```

The core insight is that physical R/W is not immediately useful until you solve translation and object discovery. Once those are solved, direct token DKOM is simpler and more stable than temporary Win32k syscall hijacking for this specific goal.

The main risks are:

- wrong CR3,
- wrong offsets,
- wrong physical translation,
- writing the wrong 8 bytes,
- restore failure.

The main advantage is:

- no shellcode,
- no SSDT hook,
- no Win32k race,
- no persistent kernel patch,
- fewer version-sensitive moving parts.

## 31. Mental Model: Three Address Spaces in This Chain

It helps to separate three address spaces that are easy to mix up:

| Layer | Example | Who normally uses it | What ASTRA sees |
|---|---|---|---|
| User virtual address | `000001A2...` | Your exploit process | Mapped view returned by driver |
| Kernel virtual address | `FFFFF8...`, `FFFF80...` | Windows kernel | Not directly accepted by map IOCTL |
| Physical address | `000000012345000` | MMU / hardware / PFNs | Input to ASTRA physical mapping |

The exploit has to connect them:

```text
kernel VA target
  -> page-table walk
  -> physical address
  -> ASTRA maps physical page
  -> user VA view
  -> user memcpy writes mapped page
  -> underlying kernel physical memory changes
```

The dangerous conceptual trap is thinking "I have physical R/W, so I have kernel R/W." Not immediately. You only have kernel R/W after you solve:

- Which kernel virtual address matters?
- Which physical page backs that virtual address?
- Is that backing page actually mapped/writable from VTL0?
- Is the object nonpaged and stable while you touch it?
- Are the offsets correct for this exact build?

## 32. What the ASTRA Mapping Bug/Quirk Means

The ASTRA mapping IOCTL returns the mapped user VA through a structure field that only preserves the low 32 bits. That is why the code reconstructs the upper 32 bits by probing with `VirtualQuery`.

The problem:

```text
real mapped VA: 0000028A`12345000
driver returns: 00000000`12345000
```

The code then tries possible high halves:

```text
(hi << 32) | returned_low32
```

and asks Windows whether that candidate is a committed mapping.

Why this is necessary:

- Without recovering the real user VA, you cannot read or write the mapped physical page.
- The driver's output is lossy.

Why the `hint_hi` cache exists:

- Mappings often appear in the same high user VA region.
- Once a correct high half is found, trying it first makes later map operations faster.

Why this is fragile:

- `VirtualQuery` only tells you the candidate address is committed, not that it is definitely the mapping you just requested.
- If another committed region has the same low 32 bits, a false positive is possible.
- In practice this is rare enough for PoC use, but it is still an assumption.

Reliability improvement:

- Validate mapping content after mapping, when possible.
- Avoid concurrent mapping-heavy behavior in the same process.
- Keep map/unmap scope tight.

## 33. Why `ReadProcessMemory` Is Used for Mapped Reads

The code uses `ReadProcessMemory(GetCurrentProcess(), mapped_va, dst, len, ...)` for reading mapped physical pages, instead of direct dereference.

Reason:

- Some mapped physical pages may trigger access issues under HVCI/VBS/EPT behavior.
- Directly dereferencing an unsafe mapping can produce a process exception or, in bad driver mapping cases, worse system behavior.
- `ReadProcessMemory` gives a more controlled user-mode copy path and a boolean failure result.

This does not make the primitive "safe". It only improves failure handling for reads.

Why writes still use `memcpy`:

- `WriteProcessMemory` to the current process could be used conceptually, but the mapped view is already writable if mapping succeeded.
- The write operation is intentionally a raw store into the mapped physical page.
- There is no safe abstraction if the target physical address is wrong.

Practical implication:

- Reads can fail gracefully more often.
- Writes remain the high-risk operation.

## 34. Page Table Entry Bits That Matter Conceptually

The walker mostly checks the present bit and large-page bit. For understanding reliability, more bits matter:

| Bit/field | Meaning | Why it matters |
|---|---|---|
| Present | Entry is valid | If clear, translation should stop. |
| RW | Writable mapping | A virtual write would respect this; physical write may bypass normal virtual permission semantics. |
| US | User/supervisor | Distinguishes user-accessible pages from supervisor pages. |
| NX | No-execute | Relevant for code execution, not direct data write. |
| PS | Large page | Changes address calculation at PDPTE/PDE level. |
| Global | TLB global mapping | Common in kernel mappings; affects invalidation semantics. |
| PFN | Physical frame number | Core output of translation. |

Important nuance:

- Physical writes do not ask the CPU whether the original virtual mapping was writable.
- But hypervisor/EPT/SLAT protections can still restrict what the VTL0 driver mapping can actually touch.

This is why physical R/W bypasses many page permission assumptions but not all virtualization-backed protections.

## 35. PCID, KVA Shadow, and Why CR3 Can Be Confusing

Modern Windows may use:

- KVA shadow/KPTI.
- PCID.
- separate user/kernel page table views.
- multiple CR3-like values per process context.

Why the exploit still works conceptually:

- The target `_EPROCESS` is in global kernel memory.
- The discovered page-table root only needs to translate the relevant kernel region.
- It does not need to be the exact user CR3 for every process.

Where confusion happens:

- A CR3 candidate may translate `KUSER_SHARED_DATA` but not every desired kernel mapping.
- KVA shadow can alter what is present in user vs kernel mode page tables.
- PCID low bits must be masked when interpreting CR3.

The code masks CR3 with a PFN mask during translation. That is essential because CR3 can contain non-address bits.

Reliability guidance:

- Do not trust CR3 only because one address translated.
- Validate multiple kernel addresses:
  - `KUSER_SHARED_DATA`.
  - `ntoskrnl` PE header.
  - `PsInitialSystemProcess`.
  - System `_EPROCESS`.
  - current process `_EPROCESS`.

## 36. Why `_EPROCESS` Being Nonpaged Matters

The direct write assumes the token field has a stable physical backing.

Paged memory can be moved out or faulted in. Nonpaged kernel objects are resident because they can be accessed at IRQLs where paging is impossible.

`_EPROCESS` is effectively nonpaged kernel memory for this purpose. That is why:

- VA->PA translation is meaningful.
- The physical page should remain resident while the process exists.
- The token field can be read/written through physical mapping.

If the target were paged:

- The page might not be present.
- Translation could fail.
- The page could be backed by a different physical frame later.
- Writing stale physical memory could corrupt unrelated data.

This is one reason token DKOM is attractive.

## 37. Why Token Swap Is One 8-Byte Write

Windows access checks often boil down to the effective token of the process/thread. For a process primary token, `_EPROCESS.Token` points to a `_TOKEN` object through `_EX_FAST_REF`.

By copying System's token fast-ref into your process:

```text
your process now points at System's token object
```

The next security-sensitive operation in that process sees the elevated token.

Why one write is enough:

- You are not modifying the token object itself.
- You are changing which token object the process references.
- Pointer-sized field controls the relationship.

Why one write is dangerous:

- A single bad pointer in `_EPROCESS.Token` can break process security operations.
- If the pointer is non-canonical or points to invalid memory, later access checks can crash.
- If reference bits/pointer alignment are wrong, behavior becomes unpredictable.

This is why reading and comparing both original and new values matters.

## 38. `_EX_FAST_REF` and Reference Semantics in More Detail

`_EX_FAST_REF` packs a pointer and a small reference count/cache value into one machine word.

On x64, kernel object pointers are aligned, so low bits are available:

```text
raw fast ref:   FFFF...ABC? 
object pointer: raw & ~0xF
low bits:       raw & 0xF
```

Copying the whole fast-ref is common because it preserves a plausible low-bit state.

But it is not semantically clean:

- The current process did not formally reference System's token through object-manager APIs.
- The original token reference is temporarily lost from the process field.
- Reference accounting may not match reality during the swap window.

Why short-lived swap is better:

- Spawn child.
- Restore original fast-ref.
- Reduce time spent with inconsistent object state.

Why not just write `system_token & ~0xF`:

- Low bits may be expected to contain a fast-ref state.
- Writing a pure pointer can work in some contexts but is less faithful to the existing representation.

## 39. Why Spawn a Child Instead of Keeping Parent SYSTEM

The code swaps the parent token, spawns `cmd.exe`, then restores the parent token.

This is a common pattern:

- Parent process is the exploit controller.
- Child process becomes the useful elevated session.
- Parent can restore itself to reduce side effects.

Why not keep the parent elevated:

- Longer exposure.
- More inconsistent token lifetime.
- More telemetry anomalies.
- More risk if parent continues doing complex operations with swapped token.

Why child process inheritance works:

- Process creation evaluates the caller's token/security context.
- The child gets a token based on the parent at creation time.

Potential issue:

- The code waits briefly on the child process handle. Waiting for process handle does not prove the child initialized fully with expected token.
- Better verification is to query the child token/SID after creation.

## 40. Direct Physical Write vs Kernel-Context Write

There are two philosophies:

Direct physical write:

```text
user mapped PA -> memcpy -> kernel object changed
```

Kernel-context write:

```text
redirect/control kernel path -> kernel code performs write
```

Direct physical write advantages:

- Simple.
- No control-flow hijack.
- No syscall table patch.
- No gadget search.
- Fewer version-sensitive moving parts.

Direct physical write disadvantages:

- Some pages may not behave correctly through physical mapping under VBS/EPT.
- It bypasses normal synchronization and object reference logic.
- If PA is wrong, no kernel exception boundary protects you.

Kernel-context write advantages:

- Uses legitimate kernel code path.
- May respect cache/mapping semantics better.
- Can avoid some weirdness with direct user mapping stores.

Kernel-context write disadvantages:

- Requires control-flow manipulation.
- Usually more detectable and crash-prone.
- Needs exact calling convention and argument shaping.

For token swap, direct physical write is usually the simpler engineering choice.

## 41. Cache Coherency, TLB, and "Will the Kernel See My Write?"

When you write through a mapped physical page, you are modifying the same underlying physical memory. On normal coherent x86 systems, other cores should see the updated memory coherently.

Why no explicit TLB flush is needed:

- You are not changing page-table entries.
- You are changing data inside an already mapped page.
- TLB caches translations, not arbitrary data contents.

When TLB/cache issues would matter more:

- If you modify PTEs/PDEs.
- If you change executable code and need instruction cache/coherency semantics.
- If device memory or uncached mappings are involved.

For `_EPROCESS.Token`:

- It is normal cached RAM.
- A normal data write should become visible.

Potential subtlety:

- If the driver maps with unusual cache attributes, behavior could be less predictable.
- Windows memory manager expects consistent cache attributes for the same physical page; violating that can cause subtle issues.

This is another reason to prefer one small write over broad memory patching.

## 42. Why Not Patch Page Tables

Some older exploit techniques modify PTEs:

- clear NX,
- make read-only pages writable,
- map user pages into kernel,
- remap code/data.

The direct DKOM approach avoids PTE patching entirely.

Why that is good:

- PTE writes are high-risk.
- HVCI/VBS makes page-table tampering less reliable.
- Wrong PTE writes crash quickly.
- PatchGuard/hypervisor integrity can detect page permission abuse.
- Token swap only needs data write, not executable memory.

When PTE patching would be considered:

- You need code execution.
- You need to modify protected code pages.
- You need to bypass SMEP/NX in old-style shellcode chains.

For this ASTRA64 route, PTE patching is unnecessary complexity.

## 43. Why Not Disable SMEP/SMAP

Classic kernel exploits often:

- disable SMEP by modifying CR4,
- ROP to kernel gadgets,
- execute user-mode shellcode in kernel context.

This route does not need that.

Why:

- No kernel instruction pointer control is needed.
- No user shellcode is executed by kernel.
- No executable payload is introduced.
- Only kernel data is modified.

This is why data-only DKOM remains relevant under modern mitigations. SMEP/SMAP/kCFG/CET mainly raise the cost of control-flow attacks; they do not directly stop every data-only security state mutation.

## 44. Why Not Patch `SeAccessCheck` or Privilege Bits

Alternative targets:

- Patch `SeAccessCheck` logic.
- Patch token privilege bitmaps.
- Patch process protection fields.
- Patch callback lists.

Why token pointer swap is preferred:

- One write.
- Easy to verify.
- Immediate broad impact.
- No code patching.
- No complex `_TOKEN` internals.
- Easy to restore.

Why not `_TOKEN.Privileges`:

- `_TOKEN` layout differs.
- Several fields interact.
- Some operations require identity, groups, integrity, logon session, not just privilege bits.

Why not `SeAccessCheck`:

- Code patching is noisy and HVCI-sensitive.
- PatchGuard risk.
- Global impact can destabilize system.

Why not callback tamper:

- PatchGuard/EDR-sensitive.
- More useful for hiding/defense evasion than simple LPE.

## 45. Validation Philosophy: Reads Before Writes

For physical-write exploitation, validation is the difference between a working PoC and random memory corruption.

Good validation chain:

1. `IA32_LSTAR` is canonical kernel pointer.
2. Kernel base page has `MZ`.
3. PE header is AMD64 PE32+.
4. `SizeOfImage` covers `LSTAR`.
5. `PsInitialSystemProcess` is exported.
6. Dereferenced System `_EPROCESS` is canonical.
7. System PID field equals 4.
8. Process list links are canonical.
9. Current PID is found.
10. Token fast-ref values mask to canonical kernel pointers.
11. Token field VAs translate to physical addresses.
12. Physical reads of both token fields match virtual reads.

Only after those checks should the write happen.

If any validation is weak, the exploit may still work in the author's VM but fail on another build.

## 46. Version Fragility: What Actually Changes Between Builds

The following can change:

- `_EPROCESS` size.
- `UniqueProcessId` offset.
- `ActiveProcessLinks` offset.
- `Token` offset.
- `ImageFileName` offset.
- protection/signature fields.
- kernel module layout.
- export presence or forwarding.
- KVA shadow behavior.
- Win32k module split/layout.

The direct route avoids Win32k changes, but still depends on `_EPROCESS`.

For your code, the most important improvement area is offset sourcing:

```text
build number -> offset table
```

is acceptable for a controlled lab, but a stronger research-grade approach is:

```text
exact build + PDB GUID -> offsets from symbols
```

or:

```text
Vergilius/PDB generated table -> strict allowlist
```

Do not silently assume unknown builds use 0x4B8.

## 47. Offset Validation Without Symbols

If symbols are unavailable, runtime sanity checks help.

For a candidate `_EPROCESS` offset set:

- `PID` at System object should be 4.
- `ActiveProcessLinks.Flink` and `Blink` should be kernel pointers.
- Walking list should eventually return to head.
- Current PID should appear once.
- `ImageFileName`, if included, should be printable ASCII near expected process name.
- `Token & ~0xF` should be canonical kernel pointer.
- Several process token pointers should differ but all be canonical/aligned.

You can reject offset sets that fail these invariants.

This is safer than:

```text
if build >= X use offsets Y
```

because Windows build detection alone does not protect against unsupported variants.

## 48. Failure Mode: Wrong `_EPROCESS.Token` Offset

If token offset is wrong, the 8-byte write may hit:

- another pointer,
- a list entry,
- flags,
- a lock,
- a counter,
- padding,
- a field used later by scheduler/security/memory manager.

Potential outcomes:

- Immediate bugcheck.
- Delayed bugcheck.
- Silent process corruption.
- No visible effect.
- System hangs later.

Why it is dangerous:

- The write is physically applied.
- No exception handler protects kernel object consistency.
- The current process object is heavily used.

Mitigation:

- Validate the original token-looking value before write.
- Check pointer canonicality and alignment.
- Optionally compare token object structure signature/fields if known.

## 49. Failure Mode: Wrong CR3

Wrong CR3 can still translate some addresses but not the ones you care about.

Symptoms:

- `ntoskrnl` walkback fails.
- `PsInitialSystemProcess` pointer is not canonical.
- System PID is not 4.
- Process list walk loops into nonsense.
- Token PA translation succeeds but token value is not a kernel pointer.

Worst case:

- It produces plausible-looking wrong physical addresses and the exploit writes them.

Mitigation:

- Multi-stage validation.
- Do not proceed on partial success.
- Fail closed.

## 50. Failure Mode: Wrong Physical Mapping View

Because ASTRA truncates mapped VA, the high-half reconstruction could theoretically pick the wrong committed user mapping.

Symptoms:

- Physical reads return inconsistent data.
- PE headers do not validate.
- Re-reading same PA returns different content unexpectedly.
- Writes have no effect on later reads.

Mitigation:

- After mapping a known PA, validate expected content.
- Keep mappings short-lived.
- Re-read after write.
- Avoid noisy allocations/mappings in the exploit process during critical stages.

## 51. Failure Mode: Protected Physical Page

Under VBS/KDP/secure pool, not all physical pages are equally accessible to VTL0.

Symptoms:

- Mapping fails.
- Read fails.
- Write silently has no effect.
- System bugchecks on access.
- Hypervisor-related fault/bugcheck appears.

For `_EPROCESS.Token`, this is less likely than for VTL1/secure kernel/KDP data, but the concept matters.

Mitigation:

- Prefer normal VTL0 nonpaged process objects.
- Avoid code pages, CI policy, secure kernel regions and page tables unless specifically studying them.
- Treat physical R/W as powerful but not omnipotent.

## 52. Failure Mode: Token Restore Is Too Late or Fails

If restore fails:

- Parent remains SYSTEM.
- Original token fast-ref may be lost.
- Object reference accounting may remain inconsistent.

If restore happens too early:

- Child process may not inherit expected token.

If parent crashes before restore:

- Kernel process object may retain swapped token until process exit or cleanup.

Mitigation:

- Save original token before write.
- Keep restore code minimal and robust.
- Re-open driver only if needed; keeping handle open may be simpler but has different operational trade-offs.
- Verify after restore.

## 53. Why Direct DKOM Is Easier to Generalize Than Shadow SSDT

Direct DKOM generalizes to other data fields:

- `_EPROCESS.Token`
- `_EPROCESS.Protection`
- process flags
- selected object fields
- handle table entries

It does not require:

- a callable kernel function,
- a syscall dispatch path,
- a gadget within range,
- a matching calling convention.

The limitation is that you must understand the target data structure. Direct DKOM is only as safe as your object model.

Shadow SSDT/general kernel-call style can perform operations without directly understanding all target object internals, but it requires much more control-flow engineering.

## 54. Why Direct DKOM Is Less "Elegant" but More Practical

From an exploit research perspective, BlackSnufkin's route is elegant:

- It builds a temporary kernel call.
- It respects HVCI-era no-shellcode constraints.
- It demonstrates syscall dispatch manipulation.

From a practical LPE perspective, your route is stronger:

- fewer steps,
- fewer version-specific structures,
- fewer global side effects,
- easier to reason about,
- smaller crash surface.

This is a common exploit engineering trade-off:

```text
more general primitive == more complexity
specific data-only goal == simpler and often more reliable
```

## 55. What "Stable Across Versions" Really Means

No Windows kernel exploit is stable across versions in the abstract. Stability must be scoped:

Stable across CPU/architecture:

- x64 page-table format is fairly stable.

Stable across Windows builds:

- `_EPROCESS` offsets are not stable.
- Win32k internals are not stable.
- export availability is moderately stable.

Stable across mitigation states:

- data-only token write is less affected by SMEP/NX/kCFG/CET.
- driver load is heavily affected by HVCI/WDAC/blocklist.
- protected memory writes are affected by VBS/KDP.

Stable across driver versions:

- ASTRA IOCTL behavior is driver-version specific.
- A vendor fix can remove or restrict the primitive entirely.

So the best description is:

```text
Direct DKOM is more version-stable than shadow SSDT hijack,
but still depends critically on EPROCESS offsets and driver behavior.
```

## 56. Practical Comparison: Direct Token Write vs Alternatives

| Goal | Technique | Pros | Cons |
|---|---|---|---|
| SYSTEM LPE | Direct token fast-ref write | One write, simple, no code exec | Offset/refcount/restore issues |
| SYSTEM LPE | `memmove` via syscall hijack | Kernel-context copy, no shellcode | Complex, race, dispatch tamper |
| SYSTEM LPE | Modify token privileges | More surgical identity retention | Token internals complex |
| PPL bypass | Modify protection fields | Targeted for LSASS/EDR access | Offset-sensitive, monitored |
| Code exec | MSR syscall hijack | Strong proof of control | Very crash-prone |
| Code exec | PTE/NX patch | Classic route | HVCI/PatchGuard/high crash risk |
| Defense evasion | Callback tamper | Can blind sensors | PatchGuard/EDR-sensitive |

For ASTRA64, the direct token write is the most pragmatic if the objective is simply to spawn SYSTEM.

## 57. Questions to Ask Before Choosing a Technique

Before selecting direct DKOM or a more advanced route, ask:

- What primitive does the driver actually expose?
- Is it physical or virtual?
- Do I need code execution, or is data-only enough?
- Is the target field in normal VTL0 nonpaged memory?
- Can I validate the address before writing?
- Can I restore safely?
- Which parts are build-specific?
- Which parts are driver-version-specific?
- Which operations patch global kernel state?
- What would cause BSOD immediately?
- What would cause delayed corruption?

For your direct ASTRA64 route, the answers are favorable:

- physical primitive is strong,
- data-only is enough,
- token field is small,
- no global dispatch patch,
- restore is simple.

## 58. Final Conceptual Takeaway

The heart of this technique is not "token stealing" by itself. The heart is building confidence in a single physical write.

Everything before the write exists to answer:

```text
Am I absolutely sure this physical address is current_eprocess.Token?
```

If yes, the exploit can be simple.

If no, every extra trick only hides the real problem.

The best ASTRA64 direct DKOM exploit engineering is therefore not more gadgets or more hooks. It is better validation, better offset sourcing, safer restore, and clearer failure handling.

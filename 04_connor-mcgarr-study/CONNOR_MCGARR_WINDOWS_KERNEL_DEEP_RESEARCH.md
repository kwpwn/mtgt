# Connor McGarr Windows Kernel Exploit Research - Deep Study Notes

Last updated: 2026-05-25

Scope:

- https://connormcgarr.github.io/paging/
- https://connormcgarr.github.io/x64-Kernel-Shellcode-Revisited-and-SMEP-Bypass/
- https://connormcgarr.github.io/Kernel-Exploitation-2/
- https://connormcgarr.github.io/examining-xfg/
- https://connormcgarr.github.io/swimming-in-the-kernel-pool-part-1/
- https://connormcgarr.github.io/swimming-in-the-kernel-pool-part-2/
- https://connormcgarr.github.io/kuser-shared-data-changes-win-11/
- https://connormcgarr.github.io/hvci/

The goal of this file is not to copy exploit code. The goal is to explain concepts, answer the "why" questions, and describe how a Windows kernel researcher should read these articles in the context of current Windows: the Windows 11 24H2/25H2 era with HVCI/VBS, kCFG, CET/shadow stack, KDP, and WDAC driver blocklist.

## 0. How to read Connor correctly

Connor writes in the style of "exploit development teaches internals". This means each article is not just about one bug. Each article uses a bug as a hook to teach a Windows concept:

- `paging`: why a virtual address is not a physical address; why PTE bits determine permissions.
- `x64 Kernel Shellcode + SMEP`: why old x64 token stealing needed to be updated; why SMEP kills ret2usr; why PTE/CR4 became a bypass path.
- `Kernel Exploitation 2`: why write-what-where is the foundational primitive; why arbitrary write can be converted to control flow.
- `XFG`: why CFG is too coarse; why type-based CFI makes function pointer hijack harder.
- `Swimming in Kernel Pool`: why modern pool exploitation is allocator research, leak engineering, and object selection, not just "overflow and win".
- `KUSER_SHARED_DATA changes`: why a static RW page was once a good code cave, and how Microsoft changed the design.
- `HVCI`: why "no code execution" does not mean the exploit is over; modern exploits can survive on data-only or existing signed code.

The correct reading framework:

```text
Bug class -> Primitive -> Missing capability -> Leak/translation/grooming -> Mitigation pressure -> Safer primitive selection
```

Example:

```text
Pool OOB read
  -> can only read beyond bounds, no write yet
  -> need to leak kernel pointer to bypass KASLR
  -> need to groom pool so the adjacent object holds a useful pointer
  -> combine with pool overflow/write primitive only after the leak
```

This is the critical mindset: an exploit is assembled from capabilities, not a single bug that instantly becomes SYSTEM.

## 1. Paging: why everything starts with the virtual address

### 1.1 Root question: what is a virtual address?

When debugging the kernel, we commonly see pointers like:

```text
fffff800`12345678
ffffa507`deadbeef
fffff780`00000000
```

These are not direct RAM addresses. They are linear/virtual addresses. The CPU must translate them through paging structures to find the real physical page.

The "why" questions:

- Why is virtual memory necessary?
- Why does each process have its own view?
- Why can the same `ntoskrnl` code be mapped into multiple contexts?
- Why does having a kernel virtual address not guarantee having the physical address?
- Why does a physical R/W driver such as ASTRA64 need VA->PA translation?

Answer: virtual memory enables isolation, sharing, lazy allocation, paging-to-disk, copy-on-write, and per-mapping permissions. Every CPU access through a virtual address must be translated by the MMU using the current page tables.

### 1.2 x64 long-mode paging

Connor emphasizes that Windows x64 uses long-mode paging. 4-level paging has the following levels:

```text
CR3 -> PML4 -> PDPT -> PD -> PT -> physical page
```

A canonical 48-bit virtual address is split into:

```text
bits 47..39: PML4 index
bits 38..30: PDPT index
bits 29..21: PD index
bits 20..12: PT index
bits 11..0 : offset within the 4 KB page
```

Each entry is 8 bytes. Each table has 512 entries. Therefore:

- 1 PTE maps 4 KB.
- 1 PDE can map a 2 MB table if the large-page bit is set.
- 1 PDPTE can map 1 GB if the huge-page bit is set.

### 1.3 Canonical address: why kernel addresses often start with `ffff`

Classic x64 does not use all 64 address bits. An address must be canonical: bit 47 is sign-extended into bits 63..48.

If bit 47 = 0:

```text
0000....
```

Typically the user range.

If bit 47 = 1:

```text
ffff....
```

Typically the kernel range.

Why does this matter? An exploit must validate pointers. A value that "looks like a pointer" but is non-canonical can cause a fault. In kernel exploitation, a bad pointer usually means BSOD, not a catchable exception.

### 1.4 What is CR3?

`CR3` holds the physical address of the PML4 base, not a virtual address. That is why a physical-memory primitive can page-walk if CR3 is known:

```text
CR3 physical PML4 base
  + index(PML4) * 8 -> PML4E
  PML4E.PFN * 0x1000 -> PDPT physical base
  + index(PDPT) * 8 -> PDPTE
  ...
```

Researcher mindset:

- If you have a kernel virtual pointer and a virtual R/W primitive: read directly.
- If you have a physical R/W primitive: you need CR3 plus a page walker.
- If you need to translate a kernel global mapping: system/process CR3 usually has the kernel half shared, but VBS/KVA shadow/PCID/LA57/large pages can complicate things.

### 1.5 PTE is a "permission contract"

A PTE contains more than just the PFN. It carries control bits:

- Present/Valid.
- Read/write.
- User/supervisor.
- Accessed.
- Dirty.
- NX/no-execute.
- Global.
- Large-page bit at upper levels.

This is what connects Connor's `paging` article to the `SMEP bypass` article.

Why does PTE matter?

- DEP/NX relies on the execute permission.
- SMEP relies on the user/supervisor bit when the kernel fetches an instruction.
- SMAP relies on the user/supervisor bit during kernel data access.
- HVCI inserts hypervisor/EPT enforcement below the guest PTE.
- KDP relies on a stronger second-level permission for selected data.

### 1.6 Example thinking: have physical R/W, want to read `_EPROCESS.Token`

Do not blindly scan physical RAM when you already have a kernel virtual address.

Cleaner pipeline:

```text
1. Find the appropriate CR3.
2. Have the VA of EPROCESS.
3. VA of token field = EPROCESS + token_offset.
4. Page-walk VA -> PA.
5. Physical read/write PA.
```

Why is this more stable than scanning?

- Reduces read/write scope.
- Less likely to touch MMIO/holes/protected ranges.
- Each PTE can be validated.
- If translation fails, stop before writing.

ASTRA64 connection: this is why physical R/W is powerful but "not yet an exploit" until address discovery and translation are in place.

## 2. Token stealing on x64: why it is still the baseline

### 2.1 What is a token?

Windows uses an access token to represent a security context:

- User/group SIDs.
- Privileges.
- Integrity level.
- Logon/session.
- Default DACL.

Every process has `_EPROCESS.Token`. On x64, this field is typically an `_EX_FAST_REF`, i.e., a pointer plus low reference bits.

Why does token stealing work?

If the attacker's process holds the `SYSTEM` process's token, subsequent access checks see the attacker process as having the SYSTEM security context.

Concept:

```text
System EPROCESS.Token -> copy pointer part -> Current EPROCESS.Token
```

### 2.2 Why you must mask `_EX_FAST_REF`

The token field is not a plain aligned pointer. The low bits are used as refcount/cache bits. If you copy or compare without masking, you may:

- Compare incorrectly.
- Write a token value with unwanted low bits.
- Destabilize reference semantics.

Mindset:

```text
token_object_pointer = Token & ~0xF
fast_ref_bits        = Token & 0xF
```

Many PoCs copy the full fast-ref value. When validating, compare the pointer part.

### 2.3 Why token stealing alone is no longer the full answer on modern Windows

Token stealing:

- Works well for local LPE.
- Data-only, minimal need for code execution.
- Not directly impacted by SMEP/kCFG/CET.

Limitations:

- Requires the correct `_EPROCESS` offset.
- The token/PPL/LSA/EDR world has many additional policy layers.
- If the exploit goal is arbitrary kernel API invocation, token stealing is insufficient.
- On some targets, spawning a SYSTEM shell is not the final objective.
- If the target field is protected by KDP or another mechanism, the write may fail/crash.

This is why Connor's HVCI post shifts to "kernel API invocation using existing code" rather than just token stealing.

## 3. SMEP: why ret2usr died

### 3.1 What does SMEP protect against?

SMEP = Supervisor Mode Execution Prevention.

If kernel mode is running and RIP points to a page with U/S=user, the CPU faults. This kills the old pattern:

```text
Kernel bug controls RIP
  -> jump to user-mode shellcode
  -> run token stealing shellcode
```

Before SMEP, an attacker could allocate RWX user memory, place shellcode there, then direct the kernel to return into it. After SMEP, the kernel may not execute user pages.

### 3.2 What does SMEP not protect against?

SMEP does not protect against:

- Kernel ROP using kernel code pages.
- Data-only token overwrite.
- Driver IOCTL that writes kernel memory directly.
- Process-kill BYOVD.
- Existing signed kernel code invocation.

Therefore SMEP kills "execute user shellcode from kernel", not "kernel arbitrary write".

### 3.3 Conceptual SMEP bypass directions

Connor presents two major directions:

1. Disable SMEP via control register manipulation.
2. Modify the PTE of a user page so it is no longer considered a user page, or run the payload from kernel-executable memory.

In modern research, understand them as:

```text
SMEP checks: kernel fetches instruction from user page?
Bypass idea A: make CPU think SMEP is off.
Bypass idea B: make page not-user/supervisor.
Bypass idea C: do not execute attacker page; use kernel code/data-only.
```

### 3.4 Why disabling SMEP via CR4 is fragile

Disabling SMEP via CR4 requires control flow inside the kernel to write CR4. This typically needs ROP/gadgets, and ROP in turn requires:

- Kernel base leak.
- Suitable gadgets.
- Stack control.
- No CET/shadow stack blocking.
- No HVCI policy making the chain pointless.
- No crash from wrong IRQL/context.

On current Windows, disabling SMEP via ROP is a good historical teaching technique, not the most stable route when you already have arbitrary kernel write. Data-only writes are usually cleaner.

### 3.5 Why PTE bit flipping is an important concept but weaker under HVCI

PTE bit flipping idea:

- Find the PTE of the user shellcode page.
- Clear the U/S bit to make the page supervisor.
- Or clear NX to make it executable.
- Kernel jumps into the page.

But HVCI/VBS inserts a second-level translation/permission layer. The guest PTE saying "executable" does not guarantee EPT/VBS will permit execution. Memory Integrity aims to prevent the kernel from executing unsigned/unapproved pages even when only the guest PTE was modified.

Therefore on Windows 11 with HVCI on:

```text
Guest PTE permission != final hardware permission policy
```

Modern mindset: PTE tampering is foundational for understanding paging, but a good exploit chain should avoid needing unsigned code execution when HVCI is on.

## 4. Write-What-Where: the most important primitive

### 4.1 What is WWW?

Write-what-where:

```text
*Where = What
```

The attacker controls:

- The value to write.
- The destination address.

It can be:

- 1-byte write.
- 4-byte write.
- 8-byte write.
- Arbitrary-length copy.
- Decrement/increment primitive.
- Masked write.

### 4.2 Why WWW does not automatically become an exploit

You still need to answer:

- Can you write to a kernel VA or only physical?
- Is KASLR bypass required?
- Is the write aligned?
- Is the write repeatable?
- Does it crash if the target page is read-only/protected?
- Is the target field covered by PatchGuard/KDP/kCFG/CET?
- Is there a read primitive to validate before/after?

An arbitrary write without a read primitive is like surgery in the dark. It can still work if the target/range is very well-known, but BSOD risk is high.

### 4.3 Old-school target: HalDispatchTable

In old arbitrary overwrite exploits, Connor used `HalDispatchTable` as a target to convert a write primitive into control-flow hijack.

Historical idea:

```text
Overwrite function pointer/global dispatch entry
Trigger legitimate kernel path that calls it
Control RIP
Run payload/ROP
Restore if needed
```

On modern Windows, this target should not be treated as a default route:

- PatchGuard can monitor global dispatch tampering.
- kCFG can block an invalid indirect call target.
- HVCI blocks unsigned shellcode.
- CET blocks return-oriented follow-up if the chain relies on return corruption.
- Symbol/export/offset changes make the technique fragile.

The value of that article is learning primitive transformation:

```text
arbitrary write -> overwrite sensitive pointer -> trigger -> code execution
```

Not treating a specific old target as a permanent recipe.

### 4.4 Modern target selection

Given WWW on Windows 11, a researcher should prefer:

1. Data-only targets with a clear observable effect.
2. Per-object targets rather than globals.
3. Targets that can be restored.
4. Targets with low PatchGuard exposure.
5. Targets that do not require unsigned code execution.

Conceptual examples:

- `_EPROCESS.Token`
- `_KTHREAD.PreviousMode`
- object access mask / handle table metadata in a lab
- callback enable flags when PatchGuard risk is well understood
- driver-owned object state when exploiting a specific driver

Do not default to:

- SSDT hook.
- IDT/GDT hook.
- Inline patch of `ntoskrnl`.
- Syscall MSR hijack.

These are more "impressive" but less stable.

## 5. Paging + SMEP + WWW: combining the three articles

The three articles `paging`, `SMEP bypass`, and `WWW` combine into a single chain of thinking:

```text
1. Kernel bug gives arbitrary write.
2. Need to know where to write -> KASLR leak.
3. Need to understand page permission model -> PTE.
4. Need to defeat SMEP/NX if executing a payload.
5. Or avoid execution entirely -> data-only DKOM.
```

This is why paging is not "theory". It determines:

- Whether you can translate VA->PA.
- Whether you can find a PTE.
- Whether you understand NX/U/S/RW bits.
- Whether you understand why HVCI makes PTE tampering insufficient.
- Whether you understand how KUSER_SHARED_DATA mapping changed.

## 6. XFG: why CFG is not enough

### 6.1 What problem does CFG solve?

CFG = Control Flow Guard.

Goal: when a program executes an indirect call/jump, the target must be in the set of valid targets.

Example:

```text
call [function_pointer]
```

If an attacker overwrites the function pointer with an arbitrary gadget address, CFG can block it.

### 6.2 CFG's weakness

CFG is coarse-grained. If the target is a valid function in the CFG bitmap, the call can proceed even if the function does not match the prototype the callsite expected.

Problem:

```text
Expected: void callback(Context*)
Attacker target: ValidExportedFunction(...)
CFG says: target valid
Program semantics: broken / abusable
```

In short: CFG asks "is this address a valid target?", not "is this the right type of function the callsite expects?"

### 6.3 What does XFG add?

XFG = eXtended Flow Guard.

Connor explains XFG as a type-based CFI layer on top of CFG:

- The compiler computes a hash based on the function prototype.
- The hash is placed near the function target.
- The callsite/dispatch compares the expected hash against the target hash.
- Mismatch -> crash/fail.

It adds the question:

```text
Is target valid?
Does target have the right type/prototype?
```

### 6.4 Why XFG is stronger than CFG

If an attacker redirects a function pointer from:

```text
void A(void)
```

to:

```text
int B(int, int)
```

CFG may allow it if `B` is a valid target. XFG will detect the prototype hash mismatch.

Exploit mindset:

- CFG bypass: find a valid target in the bitmap.
- XFG bypass: find a valid target that also has a compatible type hash.

The target space is significantly narrowed.

### 6.5 XFG's remaining weak points

Connor identifies two conceptual directions:

1. Functions with the same prototype share the same hash.
2. In theory it may be possible to find pattern/hash-compatible targets, but this is difficult and rarely useful.

More importantly: XFG is a forward-edge mitigation. It does not protect return addresses. Connor concludes that XFG must be combined with CET/shadow stack.

```text
XFG/kCFG: indirect calls/jumps
CET shadow stack: returns
```

### 6.6 How does XFG relate to the kernel?

Connor's XFG article is primarily about user-mode/compiler CFI. But the concept applies to the kernel:

- kCFG also targets forward-edge indirect calls.
- Driver callback/function pointer overwrites face CFI pressure.
- If the target is a return address/ROP chain, kCFG/XFG are not the primary mitigations; CET/shadow stack are.

Current Windows:

- kCFG has significant meaning in the kernel.
- Kernel-mode hardware-enforced stack protection on Windows 11 2022 Update+ (with hardware/VBS/HVCI prerequisites) is the direction against ROP.
- The XFG concept shows Microsoft is moving from coarse CFI -> type-aware CFI -> hardware-backed CFI.

## 7. Kernel pool: why "pool overflow" is hard today

### 7.1 What is the pool?

The kernel pool is the allocator for kernel/driver dynamic memory.

Two commonly encountered types:

- PagedPool: can be paged out, not usable at high IRQL.
- NonPagedPool/NonPagedPoolNx: always resident, used for paths that require memory to always be present.

Chunks typically have metadata/headers. On x64, the old `_POOL_HEADER` is an important concept. Segment heap/kLFH changes allocator details.

### 7.2 Why NonPagedPoolNx changed exploitation

Old thinking:

```text
Overflow pool -> place shellcode nearby -> jump
```

Modern thinking:

```text
Overflow pool -> corrupt adjacent object -> leak/write/control data/control flow
```

Why? Pool memory NX, HVCI, SMEP, kCFG, and CET all make "jump to your own bytes" harder.

### 7.3 kLFH and segment heap: why grooming is necessary

Connor focuses on kLFH. kLFH has buckets by size. Exploitation objective:

- Place the vulnerable chunk into a predictable bucket.
- Position an attacker-controlled object immediately before/after it.
- Create "holes" using allocate/free patterns.
- Place an object with a pointer/function pointer/data target into the hole.

Why is this hard?

- The kernel has many other concurrent allocator activities.
- Adjacent objects must be in the same size class/pool type.
- The object must have a useful field.
- An invalid header can crash.
- Segment heap has metadata encoding/hardening.
- Timing/concurrency makes layout non-deterministic.

### 7.4 OOB read in pool: why the leak matters

Connor's Part 1 uses OOB read to leak adjacent pool memory. From an OOB read you can:

- Leak kernel pointers.
- Bypass KASLR.
- Find object layout.
- Retrieve cookies/metadata in some cases.
- Prepare for a write primitive.

Why does the low integrity/AppContainer angle matter?

Low integrity contexts restrict APIs that leak the kernel base, such as `EnumDeviceDrivers`/`NtQuerySystemInformation`, in some contexts/versions/policies. Therefore an info leak from a kernel bug becomes a de-facto KASLR bypass.

### 7.5 Pool grooming with Windows objects

Connor uses objects that can be allocated from user mode to influence layout. General concept:

```text
Spray many same-size objects
Enable/fill kLFH bucket
Free selected objects to make holes
Allocate target/vulnerable object into predictable position
Trigger OOB read/overflow
```

Researcher questions:

- Does the object size match the vulnerable allocation?
- Does the object pool type match?
- Is the object lifetime controlled by a handle?
- Does the object leak a useful pointer?
- Does the object have a field that can be turned into arbitrary read/write?
- Does closing the handle free the chunk at the right time?

### 7.6 Part 2: from pool overflow to arbitrary read/write

Part 2 continues the idea: leak + grooming + overflow to produce a stronger primitive. Key lessons:

- Modern pool overflow usually requires multiple stages.
- Stage 1: leak KASLR/object.
- Stage 2: groom layout.
- Stage 3: corrupt object.
- Stage 4: use the corrupted object to read/write.
- Stage 5: use R/W for the final goal.

The final goal does not have to be shellcode. On current Windows, better final goals are:

- Data-only privilege change in a lab.
- Controlled kernel API invocation using existing code.
- Tamper driver-owned state.
- Tamper security tool object/state when researching defenses.

### 7.7 Why object selection is the core skill

A successful pool exploit is not the result of a "powerful" overflow. It is the result of the overflowed-into object having good semantics.

Good object:

- Allocatable from low privilege.
- Same pool type/size.
- Lifetime controllable.
- Contains pointer/length/list/function pointer.
- Has an operation that can be triggered later.
- Corruption produces read/write, not an immediate crash.

Bad object:

- Size mismatch.
- Free path validates header/cookie strongly.
- Corrupting a single bit causes a crash.
- Trigger path is rare or at the wrong IRQL.
- High PatchGuard/kCFG/CET pressure.

## 8. KUSER_SHARED_DATA: why a static page matters

### 8.1 What is KUSER_SHARED_DATA?

`KUSER_SHARED_DATA` is a shared page mapped into both user and kernel to expose data that needs to be read quickly:

- system time
- tick count
- version/build info
- processor/feature flags
- mitigation-related flags in some builds

Well-known static kernel address:

```text
fffff780`00000000
```

User-mode mirror historically:

```text
00000000`7ffe0000
```

### 8.2 Why attackers liked the KUSER_SHARED_DATA code cave

According to Connor, the structure only uses part of the page. The remaining area within the same 4 KB page historically had RW permission and a static address. If the page could be executed or accessed by the kernel in some way, it was an attractive static cave:

- No KASLR needed for the address.
- Fixed address on every boot.
- Data/payload could be written at an offset within the page.

But this is exactly why Microsoft had to change it.

### 8.3 What did Windows 11 change?

Connor observed the following on Windows 11 Insider at the time:

- The static `KUSER_SHARED_DATA` address remained.
- But the static mapping became read-only.
- Windows created a separate mapping, randomized and writable: `nt!MmWriteableUserSharedData`.
- Both mappings back the same physical memory but with different permissions.

Mental model:

```text
Static mapping:
  VA fixed, read-only, used for readers.

Writable kernel mapping:
  VA randomized, read/write, used by kernel update paths.

Same underlying data/physical backing, different virtual mappings.
```

### 8.4 Why not just randomize the static address?

The static address has compatibility value. Many code/user/kernel assumptions may read shared data at the familiar address. Randomizing the static mapping outright could cause compatibility breaks.

Instead Microsoft separated them:

- The read address remains static.
- Writes go through a separate randomized mapping.
- Static code-cave/RW abuse is reduced.

This is quintessential Windows mitigation engineering: reduce attack surface while maintaining compatibility.

### 8.5 Exploit lesson

When you see a static address:

- Do not just ask "is it static?"
- Ask "what are the current permissions?"
- Ask "is there an alias mapping?"
- Ask "is the physical backing shared?"
- Ask "where is the writable mapping, and is it KASLR-protected?"
- Ask "does HVCI/KDP/EPT have separate permissions?"

KUSER_SHARED_DATA is a case study in mapping aliasing + permissions, directly relevant to VT-rp/HLAT/KDP.

## 9. HVCI: why "No Code Execution? No Problem"

### 9.1 What does HVCI protect against?

HVCI/Memory Integrity uses VBS to move kernel code integrity into an isolated environment. Goals:

- The kernel may not execute unsigned/untrusted code.
- A writable page does not automatically become executable.
- Guest kernel PTE tampering is not sufficient to break code integrity.

As Microsoft describes it, Memory Integrity is a VBS feature; Code Integrity runs in an isolated virtual environment.

### 9.2 What does HVCI not protect against?

HVCI does not automatically protect against:

- Arbitrary writes to mutable data.
- Token DKOM.
- Process-kill driver IOCTL.
- A signed and allowed driver with a dangerous IOCTL.
- Logic bugs in signed kernel code.
- Existing-code invocation when it does not violate code integrity.

This is the core of Connor's HVCI post.

### 9.3 Why shellcode/PTE tricks fail more under HVCI

Before HVCI:

```text
Have arbitrary write
  -> modify PTE NX/U/S/RW
  -> jump to attacker bytes
```

HVCI era:

```text
Guest PTE says executable
  but hypervisor/secure CI policy may still say no
```

In other words: the VTL0 page table is no longer the sole source of truth for which kernel code is executable.

### 9.4 Connor's chain: arbitrary R/W -> existing kernel code invocation

Connor poses the question:

If shellcode execution is off the table, can I make the kernel execute pre-existing code in the order I choose?

Direction:

- Create a dummy thread.
- Leak `KTHREAD`.
- Find the dummy thread's kernel stack.
- Find an appropriate return address on the stack.
- Write a ROP chain onto the kernel stack.
- Resume the thread so the chain executes existing signed kernel code.

Why a dummy thread?

- A separate thread to manipulate.
- A separate kernel stack.
- More lifecycle control.
- Reduced impact on the main exploit thread.
- Can clean up via the terminate-thread path.

Why is this HVCI-compliant?

- No attacker-supplied bytes are executed.
- Only returns into valid code pages that are already signed/executable.
- HVCI does not forbid reusing existing executable code.

### 9.5 How does kCFG affect the chain?

kCFG blocks forward-edge indirect calls. ROP via return address is backward-edge. Therefore:

```text
overwrite function pointer -> kCFG relevant
overwrite return address -> CET/shadow stack relevant
```

Connor uses a return-oriented path to avoid kCFG issues.

### 9.6 Why CET/kernel shadow stack is the natural blocker

Kernel-mode hardware-enforced stack protection uses a shadow stack:

- CALL pushes the return address to the normal stack and the shadow stack.
- RET compares the normal return against the shadow return.
- Mismatch -> fault/bugcheck.

If an exploit writes a return address on the normal kernel stack without updating the shadow stack, RET mismatches.

Therefore on current Windows:

- HVCI on: shellcode/PTE tricks are hard.
- kCFG on: function pointer hijack is hard.
- CET kernel shadow stack on: return-address ROP is hard.

When all three are on together, an exploit should shift to:

- data-only primitive,
- legitimate kernel API path,
- logic/policy abuse,
- driver-specific semantics,
- object state corruption that does not require control-flow hijack.

## 10. Current Windows 11 thinking: 24H2/25H2 era

As of 2026-05-25, when saying "current Windows", you must treat Windows 11 24H2/25H2 servicing era with option/hardware-dependent features:

- VBS/HVCI supported broadly; HVCI default depends on clean install/OEM/hardware/policy.
- Windows 11 22H2+ has better warning/UI/default posture for Memory Integrity.
- Microsoft vulnerable driver blocklist enabled by default on Windows 11 22H2+ per Microsoft docs/support.
- Kernel-mode hardware-enforced stack protection requires Windows 11 2022 Update+, supported hardware, VBS and HVCI.
- KDP exists but is selective.
- CET/shadow stack deployment is hardware/config/compatibility dependent.

Therefore never write:

```text
Windows 11 bypassed
```

Always write:

```text
Windows 11 build X, VBS Y, HVCI Z, blocklist state, CET state, driver policy state, CPU capability.
```

### 10.1 If HVCI is off

Many older techniques remain valuable:

- PTE tampering may be more practically viable.
- SMEP bypass via CR4/PTE/ROP can be lab-reproduced.
- Pool shellcode still faces NX/SMEP resistance but with less hypervisor pressure.

But PatchGuard/kCFG/SMEP/KASLR remain issues.

### 10.2 If HVCI is on, CET is off

Connor's HVCI-style existing-code ROP becomes an important concept:

- Shellcode should not be the final plan.
- ROP/API invocation using signed code may be viable.
- kCFG forces avoiding indirect call hijack or using a valid target.
- Return stack overwrite is conceptually viable if shadow stack is not enforced.

### 10.3 If HVCI is on, CET kernel shadow stack is on

Return-address ROP faces a major blocker. In this case:

- Data-only attacks become most attractive.
- Process-kill BYOVD is still dangerous if the driver can be loaded.
- Physical/virtual R/W targeting mutable data is still dangerous.
- Logic bugs/semantic abuse in signed drivers is still dangerous.
- Control-flow exploits need more advanced call-oriented/data-oriented routes.

### 10.4 If vulnerable driver blocklist/WDAC is strict

BYOVD is blocked at the load layer:

- Known-bad drivers do not load.
- Hash/cert/rule-matched drivers are blocked.
- The attack must find a new/unlisted/already-loaded driver or a policy gap.

This is a "defense in depth" mitigation for BYOVD beyond HVCI.

## 11. Bypass taxonomy: what to understand, not what to memorize as payload

### 11.1 KASLR bypass

Goal: find the base of `ntoskrnl`/driver.

Classes:

- Legitimate API leak in a permissive context.
- Out-of-bounds read leak.
- Pool object pointer leak.
- MSR `IA32_LSTAR` read as an anchor.
- Physical memory scan with PE validation.
- Loaded module list read if the primitive allows.

Modern pressure:

- Low integrity/AppContainer restricts API leaks.
- HVCI does not directly block leaks.
- KASLR typically collapses once a read primitive is available.

### 11.2 SMEP bypass

Classes:

- Disable SMEP via CR4 write using ROP/gadgets.
- PTE U/S manipulation.
- Execute code from a supervisor executable mapping.
- Avoid execution: data-only.
- Existing code reuse.

Modern pressure:

- HVCI makes executable permission tampering harder.
- CET makes ROP harder.
- Data-only is the more stable route when the primitive allows it.

### 11.3 NX/NonPagedPoolNx bypass

Classes:

- ROP/JOP.
- Clear NX if no HVCI/second-level block.
- Corrupt object data instead of executing pool.
- Reuse existing code.

Modern pressure:

- HVCI blocks making arbitrary bytes executable.
- Pool exploitation should target object corruption.

### 11.4 CFG/kCFG bypass

Classes:

- Use a valid call target.
- Same-prototype/XFG-compatible target where applicable.
- Avoid forward-edge hijack.
- Use return-address path if CET is absent.
- Data-only.

Modern pressure:

- XFG narrows the target set by type hash.
- CET protects returns.

### 11.5 HVCI bypass

Be precise: many "HVCI bypasses" do not break HVCI. They avoid HVCI's guarantee.

Classes:

- Data-only corruption.
- Existing signed code reuse.
- Abuse a signed vulnerable driver IOCTL.
- Target mutable VTL0 data not protected by KDP.
- Avoid unsigned kernel code execution entirely.

Modern pressure:

- CET kills many ROP paths.
- KDP protects selected data.
- WDAC/blocklist kills known vulnerable drivers.

### 11.6 KDP bypass

KDP is selective. Conceptual routes:

- Target data not protected by KDP.
- Abuse a legitimate writer path.
- Remapping/page-swapping class attacks if platform protection is incomplete.
- Attack adjacent policy/logic rather than the protected field.

Modern pressure:

- The VT-rp/HLAT direction explicitly targets remapping/page-table tricks.
- Stronger VBS policy reduces the "just write physical" assumption.

## 12. How to read each Connor article like a researcher

### 12.1 Paging article checklist

Ask:

- Which address space am I in?
- What is CR3?
- Is the VA canonical?
- Is the page 4 KB, 2 MB, or 1 GB?
- Which PTE bits matter?
- Is final permission controlled only by the guest PTE or also by EPT/VBS?
- If I have physical R/W, how do I validate the translation?

### 12.2 SMEP article checklist

Ask:

- Is the chain executing user memory?
- Is SMEP actually on?
- Is HVCI on?
- Is CET shadow stack on?
- Is code execution required, or can I do data-only?
- Is PTE tampering enough on this machine?

### 12.3 WWW article checklist

Ask:

- What is the write width?
- Can I read back?
- Is the target address stable?
- Is the target global or per-object?
- Is PatchGuard likely?
- Can I restore?
- Is the final effect deterministic?

### 12.4 XFG article checklist

Ask:

- Is this forward-edge or backward-edge control flow?
- Is the target in the CFG bitmap?
- Is the target prototype-compatible?
- Is XFG enabled for this binary?
- Is the kernel equivalent kCFG involved?
- Would CET be the real blocker instead?

### 12.5 Pool articles checklist

Ask:

- Which allocator path: kLFH, VS, large?
- Pool type?
- Chunk size including header?
- Adjacent object controllable?
- Object lifetime controllable?
- Leak before write?
- Header/cookie/encoding concerns?
- Version-specific allocator behavior?

### 12.6 KUSER_SHARED_DATA checklist

Ask:

- Does the static VA still exist?
- What are the permissions of the static mapping?
- Is there a writable alias?
- Is the alias randomized?
- Same physical backing?
- Can physical R/W affect both views?
- Does KDP/VBS protect it?

### 12.7 HVCI checklist

Ask:

- Does the chain execute new code?
- Does the chain only reuse existing code?
- Is kCFG relevant?
- Is CET/shadow stack running?
- Is the target data KDP-protected?
- Is the vulnerable driver blocked?
- Can the same goal be done data-only?

## 13. Relation to your ASTRA64 direct DKOM chain

Your ASTRA64 approach:

```text
ASTRA64 physical map
  -> read MSR LSTAR
  -> find ntoskrnl base
  -> find system CR3
  -> page-walk VA to PA
  -> locate EPROCESS list
  -> write SYSTEM token into current EPROCESS token field
  -> spawn child
  -> restore token
```

Following Connor's mental model, this chain:

- Uses paging knowledge to bridge physical primitive -> virtual kernel object.
- Uses KASLR anchor from MSR/ntoskrnl base.
- Avoids SMEP because no user page is executed.
- Avoids HVCI because no unsigned kernel code is injected.
- Avoids kCFG/XFG because no indirect call is hijacked.
- Avoids CET because no return address is overwritten.
- Still has risk with KDP/protected data if the target is protected in the future.
- Still depends on driver load policy/blocklist.
- Still depends on the correct `_EPROCESS` offset for the build.

This is why data-only DKOM is highly practical in the BYOVD world.

But it is not "bypass all mitigations". It is "select a goal that most mitigations do not directly cover".

## 14. Questions a senior researcher would keep asking

When you see a bypass, do not ask "does it work?" first. Ask:

1. What is the minimum primitive required?
2. Is a read needed, or is write-only sufficient?
3. Is a kernel base leak needed?
4. Is an object pointer leak needed?
5. Is code execution needed?
6. If code execution is needed, whose code?
7. If ROP is used, does CET block it?
8. If a function pointer is used, does kCFG/XFG block it?
9. If data is written, is that data KDP-protected?
10. If a driver is used, can the driver be loaded?
11. If the write is wrong, does it crash immediately or produce silent corruption?
12. Can it be restored?
13. Is the technique version-sensitive?
14. Where do the offsets come from?
15. Is the IRQL/context correct?
16. Is there a race/concurrency window?
17. Is a global patch needed?
18. Can PatchGuard detect it?
19. If targeting Windows 11 24H2/25H2, what is the exact mitigation state?
20. If the chain "bypasses HVCI", does it actually break HVCI or just avoid its scope?

## 15. Suggested file split for next research

This file is the master map. Further deep-dives should be split into separate files:

- `01_PAGING_AND_PTE_DEEP_DIVE.md`
- `02_SMEP_NX_PTE_BYPASS_CONCEPTS.md`
- `03_WRITE_WHAT_WHERE_TARGET_SELECTION.md`
- `04_POOL_EXPLOITATION_KLFH_SEGMENT_HEAP.md`
- `05_KUSER_SHARED_DATA_MAPPING_CHANGES.md`
- `06_CFG_XFG_KCFG_CET_CONTROL_FLOW.md`
- `07_HVCI_EXISTING_CODE_INVOCATION.md`

## 16. Sources

- Connor McGarr - Paging: https://connormcgarr.github.io/paging/
- Connor McGarr - x64 Kernel Shellcode Revisited and SMEP Bypass: https://connormcgarr.github.io/x64-Kernel-Shellcode-Revisited-and-SMEP-Bypass/
- Connor McGarr - Kernel Exploitation: Arbitrary Overwrites: https://connormcgarr.github.io/Kernel-Exploitation-2/
- Connor McGarr - Examining XFG: https://connormcgarr.github.io/examining-xfg/
- Connor McGarr - Swimming in the Kernel Pool Part 1: https://connormcgarr.github.io/swimming-in-the-kernel-pool-part-1/
- Connor McGarr - Swimming in the Kernel Pool Part 2: https://connormcgarr.github.io/swimming-in-the-kernel-pool-part-2/
- Connor McGarr - KUSER_SHARED_DATA Windows 11 changes: https://connormcgarr.github.io/kuser-shared-data-changes-win-11/
- Connor McGarr - HVCI/kCFG: https://connormcgarr.github.io/hvci/
- Microsoft Learn - Memory Integrity / HVCI: https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity
- Microsoft Learn - Kernel-mode Hardware-enforced Stack Protection: https://learn.microsoft.com/en-us/windows-server/security/kernel-mode-hardware-stack-protection
- Microsoft Learn - Windows 11 silicon-assisted security: https://learn.microsoft.com/en-us/windows/security/book/hardware-security-silicon-assisted-security
- Microsoft Learn - CFG compiler option: https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-control-flow-guard

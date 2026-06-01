# R/W Primitives vs HVCI/VBS Deep Dive

Last updated: 2026-05-25

In this file, "HVI" means HVCI / Hypervisor-enforced Code Integrity / Memory Integrity. The Windows UI usually calls it Memory Integrity; technical documentation commonly uses HVCI or Hypervisor-protected Code Integrity.

Goals:

- Explain what HVCI still blocks once you already have an R/W primitive.
- Compare virtual-address R/W versus physical-memory R/W.
- Explain "bypass" directions in the research sense: not necessarily breaking HVCI, but choosing a final technique that falls outside HVCI's guarantee.
- Separate techniques that remain practical on Windows 11 24H2/25H2-era from those that are historical/lab-only or crash-prone.
- Present by concept, reasoning, tradeoffs, success conditions, and failure conditions.

Related files:

- `CONNOR_HVCI_KCFG_DEEP_DIVE_VI.md`
- `VT_RP_HLAT_DEEP_DIVE_VI.md`
- `MITIGATION_MATRIX.md`
- `..\04_connor-mcgarr-study\07_HVCI_EXISTING_CODE_INVOCATION.md`
- `..\03_byovd\00_index-and-matrix\BYOVD_PRIMITIVE_MATRIX.md`

## 1. Reframing the question: what does "bypass HVCI" actually mean?

HVCI is not a firewall that blocks every dangerous kernel behavior. HVCI is code integrity enforcement backed by VBS/hypervisor.

It focuses on:

```text
Preventing VTL0 kernel from executing code that is not trusted/validated.
Preventing writable kernel data pages from arbitrarily becoming executable code pages.
Protecting certain metadata/code integrity state that the normal kernel should not modify.
```

It does not automatically guarantee:

```text
No arbitrary write.
No token DKOM.
No PreviousMode abuse.
No process-kill driver.
No unsafe signed driver IOCTL.
No data corruption on mutable kernel data.
No ROP if CET/shadow stack is not enabled.
```

Therefore "bypass HVCI" can have three very different meanings:

| Meaning | Description | Difficulty / significance |
|---|---|---|
| Directly break HVCI | Make HVCI allow unsigned/new kernel code to execute against policy | Very hard; usually requires a bug in secure kernel/hypervisor/CI path |
| Avoid HVCI's scope | Do not execute new code; use data-only or existing signed code | More practical; this is the majority of public research |
| Disable/corrupt CI policy | Tamper DSE/CI callbacks/options, boot/policy tricks | Version- and mitigation-sensitive; high PatchGuard/KDP/WDAC pressure |

When reading a writeup, always ask:

```text
Does this technique break HVCI, or does it merely avoid HVCI?
```

If the chain only swaps a token via arbitrary write, it does not prove HVCI is broken. It proves HVCI is not a general-purpose data integrity mitigation.

## 2. HVCI/VBS memory model to understand

Without HVCI:

```text
VA -> guest PTE -> PA
permission mostly decided by normal PTE
```

With VBS/HVCI:

```text
VTL0 VA
  -> VTL0 guest page table
  -> GPA / guest physical address
  -> EPT/SLAT controlled by hypervisor/secure kernel policy
  -> SPA / system physical address
```

Key points:

- The VTL0 kernel is no longer the highest trust boundary.
- VTL0 can modify its own guest PTEs, but EPT/SLAT still has the "final say" on certain permissions.
- HVCI uses VBS to make Code Integrity hard for the normal kernel to modify.
- KDP uses VBS/SLAT to make selected data read-only to VTL0.

Connor's main point: the hypervisor's physical memory permissions trump the guest's virtual memory permissions. If the guest PTE says writable/executable but the EPTE says read-only/no-execute, the access still fails.

## 3. What do you actually have with an R/W primitive?

Not all R/W primitives are equal. Describe them along 9 dimensions:

```text
1. Address domain: virtual VA or physical/GPA?
2. Direction: read only, write only, read/write?
3. Width: 1/2/4/8 byte, arbitrary length, page map?
4. Alignment: any address or aligned?
5. Repeatability: one-shot or repeatable?
6. Context: current process CR3, system CR3, kernel global mapping?
7. Validation: can you read back?
8. Fault behavior: does an invalid address fail gracefully or BSOD?
9. Protection boundary: is it limited by HVCI/KDP/EPT/SMAP/IRQL?
```

Example:

```text
8-byte virtual arbitrary write + no read
```

is very different from:

```text
map arbitrary physical page read/write + read-back + unmap
```

and both differ from:

```text
decrement-one-byte primitive into KTHREAD.PreviousMode
```

## 4. Virtual R/W vs Physical R/W: which is "better"?

Short answer:

```text
Virtual kernel R/W is better for final exploitation.
Physical R/W is better for low-level introspection and translation games.
```

But both have conditions.

### 4.1 Virtual kernel R/W

Virtual R/W means the primitive reads/writes kernel virtual addresses:

```text
read64(fffff800`...)
write64(ffffa507`...)
```

Advantages:

- Close to the Windows object model: `_EPROCESS`, `_KTHREAD`, module list, callback table.
- No need to write your own VA->PA page walker.
- Less risk of hitting MMIO/physical memory holes.
- Easier to validate objects/lists/pointers.
- Faster path to token DKOM, PreviousMode, callback/object tampering.
- If primitive is stable, exploit development is faster than physical R/W.

Disadvantages:

- Requires kernel virtual addresses/leaks.
- KASLR and object address discovery still need to be solved.
- If target page is read-only/KDP/EPT protected, writes may fail or crash.
- Not easy to inspect page tables/physical memory without a mapping.
- If primitive is constrained to current process address space, it may not reach kernel globals in some contexts.

Best use:

- Token DKOM.
- PreviousMode.
- Kernel object state corruption.
- Primitive upgrade via objects like I/O Ring.
- Per-object data-only route.

### 4.2 Physical memory R/W

Physical R/W in a Windows VBS context typically means the ability to map/read/write physical/GPA memory from the VTL0 view through a dangerous driver/API:

```text
map physical page -> user VA -> memcpy/read
```

Advantages:

- Can read page tables if CR3 is known or scanned.
- Can VA->PA translate any mapped object.
- Can bypass some virtual address restrictions.
- Can use MSR/low-stub/CR3/page-table introspection to bootstrap.
- Well-suited to drivers like ASTRA64/eneio64/ThrottleStop/Lenovo.
- Read-back is usually very reliable if the map API is stable.

Disadvantages:

- Physical R/W does not automatically bypass the hypervisor. The VTL0 physical view is still subject to EPT/SLAT policy for protected pages.
- Requires VA->PA bridge: CR3, page walker, large pages, KVA shadow, canonical VA, page boundaries.
- Risk of mapping MMIO/holes/device memory with wrong cache attributes.
- Risk of writing the wrong physical page if the object has moved/been freed.
- HVCI/KDP protected GPA may not be writable from VTL0.
- Higher debug/BSOD risk than virtual R/W if not carefully validated.

Best use:

- KASLR recovery via `IA32_LSTAR`, low stubs, PE scan.
- Page-table introspection.
- Translating kernel objects to PA for data-only writes.
- Comparing/validating memory state.
- Researching the remapping/page swapping class.

### 4.3 Decision table

| Goal | Virtual R/W | Physical R/W |
|---|---|---|
| Token DKOM | Very good if EPROCESS VA is known | Good once VA->PA is solved |
| PreviousMode | Very good if KTHREAD VA/offset is known | Good but requires translation |
| KASLR bypass | Needs a leak path | Strong with MSR/physical scan/low stub |
| Page table tamper | Possible if PTE VA is known | Very suitable since PML4/PTE are physical structures |
| HVCI code execution | Not automatic | Not automatic |
| KDP protected data write | Blocked if protected | May also be blocked by EPT/SLAT |
| Object state data-only | Easier | Strong but more complex |
| Primitive upgrade | Easier if object VA/leak available | Requires virtual/object bridge |
| BSOD risk | Lower if primitive is clean | Higher if PA map/write is wrong |

## 5. Golden rule: R/W primitive does not equal code execution

Previously:

```text
arbitrary write -> function pointer hijack -> shellcode -> SYSTEM
```

Modern Windows:

```text
arbitrary write
  -> data-only
  -> existing signed code
  -> primitive upgrade
  -> policy/object semantic abuse
```

HVCI makes "execute my bytes" hard. kCFG makes "overwrite function pointer to arbitrary target" hard. CET makes "overwrite return address to ROP" hard. KDP makes "write selected protected data" hard. WDAC/blocklist makes "load known bad driver" hard.

Therefore when you have R/W, choose a final goal with the least mitigation pressure.

## 6. Technique family A: Data-only DKOM

### 6.1 Concept

Data-only DKOM = do not execute new code; only modify kernel objects/data so Windows behaves differently on its own.

Examples:

- `_EPROCESS.Token` swap.
- `_KTHREAD.PreviousMode` change.
- Process/object protection flags in lab.
- Driver-owned policy/state field.
- Handle/object access state.

HVCI impact:

```text
Low, if target data is mutable and not KDP-protected.
```

Why? HVCI protects code integrity, not every data field.

### 6.2 Token DKOM

Goal:

```text
Current process security context -> SYSTEM
```

Why it works:

- Access checks use the token.
- If the current process token points to the SYSTEM token, the process has SYSTEM privileges.

Why it is attractive:

- No shellcode.
- No function pointer hijack.
- No ROP.
- kCFG/CET irrelevant.
- HVCI mostly irrelevant.
- Original token can be restored.

Why it is limited:

- Provides LPE, not arbitrary kernel API invocation.
- Requires correct `_EPROCESS` offsets.
- Requires EPROCESS address discovery.
- Token is `_EX_FAST_REF`; low bits matter.
- Wrong write can kill the process/system.

Virtual R/W path:

```text
find System EPROCESS VA
find current EPROCESS VA
read System Token
write current Token
restore later
```

Physical R/W path:

```text
find/derive CR3
find EPROCESS VA
translate token field VA -> PA
physical read/write 8 bytes
restore later
```

HVCI bypass classification:

```text
Not a direct HVCI bypass.
It is an HVCI-agnostic data-only LPE.
```

### 6.3 PreviousMode

`KTHREAD.PreviousMode` tells kernel syscall paths whether the caller came from user mode or kernel mode.

If a weak primitive can change:

```text
UserMode = 1
```

to:

```text
KernelMode = 0
```

some kernel APIs may skip user-mode probing/validation assumptions and allow normal syscalls to touch kernel addresses.

Why it is powerful:

- A tiny write/decrement can become broad R/W.
- Does not require code execution.
- HVCI/kCFG/CET mostly irrelevant.

Why it is fragile:

- Offset is build-sensitive.
- Must target the correct thread.
- Must restore.
- If left as KernelMode, the process/thread can behave dangerously.
- Not all syscalls become useful; behavior depends on API path.

Best primitive:

- Virtual R/W or limited write to KTHREAD VA is easiest.
- Physical R/W needs KTHREAD VA->PA translation.

HVCI classification:

```text
Data-only semantic abuse; avoids HVCI's scope.
```

### 6.4 Object flags / policy fields

Examples in research:

- per-process flags,
- protection levels,
- object callback lists,
- handle table entries,
- driver-specific allow/deny state.

Risks:

- PatchGuard may monitor some global structures.
- PPL/protection semantics changed across versions.
- EDR/security products may monitor.
- Wrong field may be reference-counted/locked.

Rule:

```text
Prefer per-object, short-lived, restorable changes over global persistent patches.
```

## 7. Technique family B: Primitive upgrade

Sometimes the first primitive is weak:

- write-only,
- one 8-byte write,
- increment/decrement,
- arbitrary write without read,
- read without write,
- physical-only mapping.

Goal: turn it into full virtual R/W.

### 7.1 I/O Ring style upgrade

Yarden Shafir's I/O Ring research shows a Windows 11 post-exploitation idea: one or a few arbitrary writes can corrupt an object pointer so that normal I/O Ring operations become kernel read/write.

High-level concept:

```text
1. Find a kernel object whose trusted internal pointer later controls copy source/destination.
2. Use a small write to redirect that pointer to an attacker-controlled descriptor array.
3. Use legitimate kernel operations to perform reads/writes.
```

Why this matters:

- It avoids raw shellcode.
- It converts a limited write into full R/W.
- It uses normal kernel behavior after the corruption.
- It is very "Windows-current": data-based, object-semantic, no unsigned code.

Mitigation pressure:

- HVCI: low, no new code.
- kCFG/CET: low, no control-flow hijack.
- KASLR/object leak: required.
- Object layout/version: important.
- Microsoft may harden specific objects/fields.

Research lesson:

```text
The best target is often not Token.
It is an object that upgrades your primitive into a general read/write engine.
```

### 7.2 Fake kernel structure / confused trust

General class:

```text
Kernel object has pointer to trusted kernel-resident structure.
Attacker corrupts pointer to fake structure.
Kernel later trusts fields inside fake structure.
```

Why HVCI does not stop it:

- Kernel is executing legitimate code.
- The bug is data trust, not code trust.

Why it is version-sensitive:

- Structure layouts change.
- Probe/capture hardening can be added.
- Object validation can be tightened.

### 7.3 From physical R/W to virtual R/W

Physical-only drivers often need an upgrade:

```text
physical R/W
  -> find CR3
  -> page walk
  -> implement vread/vwrite
  -> now behave like virtual kernel R/W
```

This is what makes ASTRA64-style chains practical.

Important:

- Page walk must support large pages.
- Must split accesses across page boundaries.
- Must validate present bits.
- Must avoid protected/unmapped/MMIO pages.
- Must cache high mapping bits carefully if driver returns a truncated user-mode mapping pointer.

## 8. Technique family C: Existing-code invocation

### 8.1 Concept

HVCI blocks executing unsigned/new kernel code. But signed executable kernel code already exists.

Question:

```text
Can an R/W primitive make the kernel call existing code with controlled arguments?
```

Connor's HVCI post explores this by steering execution through a controlled/dummy thread stack and a ROP-like chain.

### 8.2 Why it works against HVCI but not against CET

HVCI:

```text
Are executed bytes trusted/signed/executable?
```

Existing code:

```text
Yes.
```

CET/shadow stack:

```text
Did the return address match the hardware shadow stack?
```

ROP overwrite:

```text
No, if CET kernel shadow stack is enforced.
```

So:

| Mitigation | Impact |
|---|---|
| HVCI | Existing-code reuse can be HVCI-compliant |
| kCFG | Less direct if using returns, more direct for function pointer/COP |
| CET kernel shadow stack | Strong blocker for return-address ROP |
| SMAP/IRQL | Can break argument/state handling |

### 8.3 When to consider existing-code invocation

Consider it when:

- Need kernel API, not just token LPE.
- HVCI is on.
- CET kernel shadow stack is off/audit/not available.
- Have reliable arbitrary R/W.
- Can identify thread/KTHREAD/stack state.
- Can clean up.

Avoid it when:

- CET kernel shadow stack is enforced.
- No reliable read primitive.
- Stack layout is unstable.
- IRQL/context is unknown.
- Only need simple LPE; token DKOM is simpler.

### 8.4 Why virtual R/W is better here

Existing-code invocation usually needs:

- KTHREAD address,
- kernel stack bounds,
- return address search,
- module/gadget addresses,
- argument/state placement.

Virtual R/W is easier. Physical R/W must first become virtual R/W through translation.

## 9. Technique family D: PTE and page-table manipulation

### 9.1 Classic uses

PTE manipulation can:

- Clear NX.
- Clear U/S to defeat SMEP.
- Set R/W.
- Remap VA to a different PFN.
- Create an alias mapping.

Old exploit goal:

```text
make user shellcode look supervisor+executable
```

Modern problem:

```text
HVCI/EPT/SLAT can still deny execute/write despite guest PTE changes.
```

### 9.2 PTE tamper vs HVCI

Without HVCI:

```text
PTE bit flip may be enough.
```

With HVCI:

```text
PTE bit flip often not enough for executable code.
```

Why:

- HVCI controls kernel executable permissions through secure CI + hypervisor.
- A writable data page becoming executable violates the HVCI model.
- EPTE can override guest PTE permission.

PTE tamper is still useful for:

- translation research,
- remapping attacks,
- data alias experiments,
- non-HVCI lab environments,
- understanding mitigations.

But it should not be your default code-execution plan on HVCI-on systems.

### 9.3 Remapping/page swapping

Concept:

```text
Protected virtual address VA normally maps to protected physical page A.
Attacker changes guest PTE so VA maps to attacker-controlled physical page B.
Code later reads VA and sees attacker's data.
```

This is not "write protected page A". It is "change the translation so VA no longer points at A".

Why it mattered:

- KDP protects the GPA backing protected data with SLAT read-only.
- If KDP only protects page A, but code accesses VA and VA now maps to B, the attacker may influence what code reads.

Fortinet described this class around DSE/CI data; Satoshi's VT-rp/HLAT posts explain why Intel added mechanisms to counter remapping attacks more directly.

Requirements:

- Kernel read/write or physical/page-table access.
- PTE base or page-table traversal.
- A controlled replacement page.
- Knowledge of target VA and semantics.
- Timing/consistency.

Mitigation pressure:

- KDP periodic verification / hardened mapping checks.
- VT-rp/HLAT direction.
- PatchGuard/Secure Kernel Patch Guard.
- HVCI/SLAT for protected pages.
- Build-specific CI/KDP changes.

Classification:

```text
This is closer to a KDP/remapping bypass class than a generic HVCI bypass.
```

### 9.4 Physical R/W advantage in page-table attacks

Physical R/W is better than virtual R/W for page-table attacks because:

- CR3/PML4/PTE pages are physical structures.
- You can inspect raw entries.
- You can translate without relying on a kernel helper.
- You can reason about PFNs.

But:

- Changing page tables is high-risk.
- TLB shootdown/cache coherency matters.
- HVCI/secure kernel may detect/override.
- A wrong entry means an instant crash or silent corruption.

## 10. Technique family E: DSE/CI tamper

### 10.1 Historical goal

DSE/CI tamper tries to allow unsigned/untrusted drivers to load by changing code integrity state.

Old target:

```text
ci!g_CiOptions
```

Modern pressure:

- KDP protects CI policy data in modern Windows.
- HVCI moves CI trust decisions into the VTL1/SKCI path.
- PatchGuard/Secure Kernel Patch Guard.
- WDAC/blocklist.
- Windows 11 CI changes.

### 10.2 Page swapping and callback swapping

Public research describes:

- Page swapping: remap protected CI data VA to a controlled page.
- Callback swapping: alter the callback table so ntoskrnl calls a different CI validation callback.

Why these are attractive:

- They use data corruption, not code patching.
- HVCI does not allow unsigned code, so attackers target the policy/validation path.

Why they are fragile:

- Very build-specific.
- High PatchGuard/SKPG risk.
- KDP/VT-rp direction specifically pressures remapping.
- DSE tamper is heavily monitored.
- WDAC and blocklists may still apply.

Practical research conclusion:

```text
Good to understand.
Poor choice as a default stable LPE path.
```

If your goal is "get a SYSTEM shell", token DKOM is simpler. If your goal is "load an arbitrary unsigned kernel driver under HVCI", you are fighting the strongest part of the platform.

## 11. Technique family F: MSR/syscall path hijack

An MSR write primitive can change `IA32_LSTAR`, the syscall entry point.

Why it is powerful:

- Affects every syscall on that CPU/path.
- Can redirect execution very early.

Why it is dangerous:

- Global/high-frequency path.
- Race/concurrency risk.
- SMEP/HVCI still matter for target code.
- PatchGuard/stability risk.
- Wrong value = immediate BSOD.
- Multi-core synchronization/restore is hard.

HVCI angle:

- If redirected to unsigned memory, HVCI/SMEP will likely block or crash.
- If redirected to existing code, you still need controlled state/arguments.

Practical conclusion:

```text
MSR read is great for KASLR.
MSR write is usually a last-resort/high-risk path.
```

## 12. Technique family G: Process-kill / semantic BYOVD

If a driver provides:

```text
terminate PID
disable callback
unload/filter control
memory scan exclude
write config
```

then no generic kernel R/W is needed.

HVCI impact:

- Low if the driver is signed and allowed to load.
- Main mitigation is WDAC/blocklist and driver access control.

This is why process-killer BYOVDs remain operationally valuable even though they are not "full R/W".

Research framing:

```text
Some primitives bypass the need to bypass HVCI at all.
The driver already performs the desired privileged action.
```

## 13. What the current Windows era changes

For Windows 11 24H2/25H2-era research, record the exact state:

```text
Build:
VBS running:
HVCI / Memory Integrity:
Kernel-mode Hardware-enforced Stack Protection:
KDP target protected?:
WDAC policy:
Vulnerable driver blocklist:
Secure Boot:
CPU MBEC/GMET/CET support:
Test signing/debug mode:
```

Do not say:

```text
works on Windows 11
```

Say:

```text
works on Windows 11 build X with HVCI on/off, CET on/off, blocklist state Y.
```

### 13.1 HVCI on, CET off

Likely viable:

- token DKOM,
- PreviousMode,
- object data-only,
- I/O Ring style primitive upgrade if applicable,
- existing-code ROP/call if kCFG/CET constraints are handled.

Less viable:

- PTE -> shellcode execution,
- raw pool shellcode,
- user shellcode ret2usr,
- permanent SSDT/inline patches.

### 13.2 HVCI on, CET on

Likely viable:

- data-only,
- process-kill driver semantics,
- object/state corruption,
- primitive upgrade not requiring return hijack.

Much harder:

- return-address ROP,
- stack pivot,
- Connor-style dummy thread ROP if shadow stack is enforced.

### 13.3 HVCI on, KDP target protected

If target is protected data:

- direct VA write fails,
- physical mapped write may still fail due to SLAT/EPT,
- page swapping/remapping may be the research angle but is actively mitigated,
- targeting alternate unprotected state may be easier.

### 13.4 Strict WDAC/blocklist

If using BYOVD:

- known vulnerable driver may not load,
- known incompatible driver may be blocked,
- driver write-to-disk may be blocked by ASR,
- an already-loaded driver or a new unknown vulnerable driver becomes the realistic path.

## 14. Technique ranking by stability

Assuming R/W primitive already exists:

| Rank | Technique | Stability | Version sensitivity | BSOD risk | HVCI pressure |
|---:|---|---|---|---|---|
| 1 | Data-only token DKOM with validated offsets + restore | High in lab | Medium | Medium if wrong offset | Low |
| 2 | PreviousMode with exact KTHREAD offset + restore | Medium | High | Medium/high | Low |
| 3 | Primitive upgrade through trusted object semantics | Medium/high | High | Medium | Low |
| 4 | Existing-code invocation without CET | Medium | High | High | Medium |
| 5 | Process-kill semantic BYOVD | High for intended target | Low/medium | Low/medium | Low |
| 6 | Page-table permission tamper for shellcode | Low on HVCI systems | High | High | High |
| 7 | KDP remapping/page swapping | Low/experimental currently | High | High | High |
| 8 | DSE/CI callback/policy tamper | Low for current stable use | Very high | High | High |
| 9 | MSR syscall hijack | Low | Medium/high | Very high | High |

Why token DKOM ranks high:

- minimal writes,
- no code execution,
- no global patch,
- reversible.

Why DSE/MSR ranks low:

- fights platform core,
- global effect,
- heavily monitored/protected,
- easy BSOD.

## 15. R/W primitive decision workflow

Use this when reading a new exploit:

```text
1. What primitive exactly?
   VA read/write? Physical map? write-only? limited?

2. Can I read back?
   If no read, choose targets that need one/few deterministic writes.

3. Can I discover target addresses?
   KASLR, object leak, CR3, page walk.

4. Is final goal code execution or state change?
   Prefer state change under HVCI.

5. Is target data protected?
   KDP/CI policy/CFGRO/secure kernel state.

6. Is control-flow hijack involved?
   kCFG for forward-edge, CET for return-edge.

7. Is the change global or per-object?
   Prefer per-object.

8. Can I restore?
   If not, PatchGuard/stability risk rises.

9. Is driver/load path allowed?
   WDAC/blocklist/HVCI compatibility.

10. What is exact Windows build and mitigation state?
```

## 16. Examples of choosing the right path

### Example A: Physical R/W driver, HVCI on, goal SYSTEM shell

Bad route:

```text
Map user shellcode page -> flip PTE -> jump to it
```

Why bad:

- HVCI may block execution.
- SMEP/NX/PTE details are fragile.
- Need control-flow hijack.

Better route:

```text
physical R/W -> VA/PA page walk -> EPROCESS.Token write -> spawn child -> restore
```

Why better:

- data-only,
- no shellcode,
- no kCFG/CET issue,
- minimal write.

### Example B: Virtual write-only primitive, no read, HVCI on

Bad route:

```text
patch code / patch SSDT
```

Why bad:

- no read-back,
- HVCI/PatchGuard/kCFG pressure,
- global corruption.

Better route:

```text
one/few deterministic object pointer writes if object address is known
or token write if values are known/leaked by another channel
or upgrade primitive through an object designed for later kernel copy
```

### Example C: Need arbitrary kernel API, not just SYSTEM

Token DKOM may not be enough.

Options:

- existing-code invocation if CET is off,
- object/driver semantic route,
- legitimate kernel worker/callback path if safe and valid under kCFG,
- avoid unsigned shellcode.

### Example D: Want to tamper CI/DSE

Ask first:

```text
Why not avoid this entirely?
```

CI/DSE tamper fights HVCI/KDP/SKCI directly. It is useful research, but usually offers poor stability compared with data-only LPE.

## 17. Virtual R/W vs physical R/W final judgment

If I already have both:

```text
Use physical R/W for discovery/translation/validation.
Use virtual R/W for final object-level exploitation.
```

If I only have virtual R/W:

```text
Good. Focus on object addresses, symbol offsets, data-only targets, primitive upgrade.
```

If I only have physical R/W:

```text
First build reliable VA->PA.
Then treat it as virtual R/W for the final target.
```

If I only have write-only:

```text
Avoid complex targets. Need deterministic one/few-write data-only or object-upgrade path.
```

If I only have read:

```text
You have KASLR/object leak. Need a second bug, side effect, MMIO/state-machine abuse, or transform.
```

## 18. What to add to per-driver writeups

For every BYOVD driver, add:

```text
Primitive domain:
  virtual / physical / MSR / process semantic / limited

Can read:
Can write:
Write width:
Can map page:
Needs VA->PA:
Can read MSR LSTAR:
Can find CR3:
HVCI-compatible load:
Blocklist status:
Best final technique:
Avoided techniques:
KDP risk:
kCFG/CET risk:
PatchGuard risk:
BSOD risk:
Version sensitivity:
```

This will make the resource much more useful than just listing CVEs.

## 19. Common wrong assumptions

### "Physical R/W bypasses HVCI"

Wrong. Physical R/W from VTL0 is still subject to hypervisor/SLAT policy for protected pages. It is powerful, but not outside VBS.

### "HVCI stops token stealing"

Usually wrong. Token stealing is data-only. HVCI blocks unsigned code execution, not every mutable data write.

### "KDP protects all data"

Wrong. KDP protects selected data. Unprotected kernel objects remain mutable.

### "PTE bit flip bypasses HVCI"

Often wrong on modern systems. The guest PTE is not the final execute permission under HVCI.

### "kCFG stops ROP"

Wrong. kCFG protects forward-edge indirect calls/jumps. CET/shadow stack protects return-address tamper.

### "If driver is signed and HVCI-compatible, it is safe"

Wrong. It can still expose unsafe semantics. HVCI validates code trust, not every IOCTL authorization or design.

## 20. Detailed primitive matrix

### 20.1 Read-only virtual primitive

Capability:

```text
read kernel VA -> user
```

What it gives:

- KASLR defeat if you can read module pointers.
- Object discovery.
- Offset validation.
- Token value discovery.
- Page table / PTE read if PTE VA is known.

What it does not give:

- No direct corruption.
- No LPE by itself unless paired with a side effect.

HVCI impact:

- Low. HVCI is not primarily a read-confidentiality protection.
- KDP mainly protects writes, not ordinary reads, though some sensitive regions may have additional protection.

Best use:

```text
Turn an unknown target into a deterministic target for a later write.
```

Example thinking:

```text
read PsInitialSystemProcess
read System EPROCESS token
read current EPROCESS token
validate offsets before any write
```

### 20.2 Write-only virtual primitive

Capability:

```text
write chosen value to kernel VA
```

What it gives:

- One or a few deterministic data changes.
- Pointer overwrite if target address is known.

What it lacks:

- Cannot validate target content.
- Cannot discover addresses.
- Harder to restore.
- Much higher BSOD risk.

Best targets:

- already-known object address,
- known stable field,
- one-shot primitive upgrade object,
- `PreviousMode`/token only if values/addresses are known.

Avoid:

- page-table tamper,
- CI/DSE tamper,
- global callback patching,
- anything requiring read-modify-write.

HVCI impact:

- Low if writing mutable data.
- High if trying to create code execution.

### 20.3 Full virtual R/W

Capability:

```text
read/write arbitrary kernel VA
```

This is the most convenient exploit primitive.

Why:

- You can validate before writing.
- You can backup/restore.
- You can walk linked lists.
- You can parse PE/kernel module data.
- You can locate per-process/per-thread objects.
- You can build a clean data-only path.

Best paths:

- token DKOM,
- `PreviousMode`,
- primitive upgrade,
- object state corruption,
- existing-code invocation if needed and CET allows.

HVCI impact:

- Does not stop mutable data R/W.
- Stops the easy transition from R/W to unsigned code execution.

### 20.4 Physical read-only

Capability:

```text
read physical/GPA pages
```

What it gives:

- raw memory inspection,
- CR3/page-table discovery,
- KASLR anchors,
- PE scan,
- physical validation.

What it lacks:

- no corruption,
- needs VA->PA to understand Windows objects.

Best use:

```text
bootstrap virtual knowledge from raw memory
```

### 20.5 Physical write-only

Capability:

```text
write physical/GPA pages
```

Dangerous because:

- without read, you may not know what lives at that PA,
- physical memory reuse can make a stale PA dangerous,
- page holes/MMIO can behave unpredictably.

Useful only if:

- exact PA was discovered elsewhere,
- write is minimal,
- target is stable/nonpaged,
- restore not required or backup is known.

HVCI/KDP:

- If GPA is protected read-only by SLAT, write may fail/bugcheck.
- If unprotected mutable page, write can work.

### 20.6 Full physical R/W

Capability:

```text
map/read/write physical/GPA pages
```

This is powerful but raw.

Correct pipeline:

```text
physical R/W
  -> find CR3
  -> page-table walk
  -> implement virtual read/write
  -> choose data-only final target
```

Do not jump directly to:

```text
scan RAM for token-looking bytes and write
```

unless it is a throwaway lab. Translation beats guessing.

## 21. What happens when you write to different page classes?

| Target page class | Virtual R/W result | Physical R/W result | HVCI/KDP note |
|---|---|---|---|
| Mutable kernel data | Usually works if address is valid | Usually works if PA is valid | HVCI low pressure |
| Executable kernel code page | Usually blocked/read-only/bugcheck | Usually blocked if protected by SLAT/HVCI | HVCI high pressure |
| CI/KDP protected policy data | Write likely blocked/faults | Write may still be blocked by SLAT | KDP high pressure |
| Page table page | Can work if writable and reachable | Physical R/W naturally suited | Detection/stability high risk |
| User page | Kernel VA primitive may not target it | Physical maps backing page | SMEP/SMAP/NX matter if executing/accessing |
| MMIO/device memory | VA access depends on mapping | Physical map may have side effects | High hardware/state risk |
| Freed/reused pool page | Writes corrupt current occupant | Same | Race/use-after-free risk |

Key point:

```text
Physical write is not a magic write to DRAM outside all policy.
On VBS systems, VTL0 access still goes through translation/protection chosen by hypervisor/secure kernel for protected GPAs.
```

## 22. Case study: ASTRA64-style physical R/W

ASTRA64 class primitive:

```text
physical map page
MSR read
```

Good strategy:

```text
1. Use MSR read for LSTAR.
2. Use LSTAR to recover ntoskrnl base.
3. Find CR3 using stable mapped kernel/user shared data assumptions.
4. Page-walk kernel VAs.
5. Resolve PsInitialSystemProcess.
6. Walk EPROCESS list.
7. Translate token fields VA->PA.
8. Perform minimal token write.
9. Spawn child.
10. Restore.
```

Why this is better than shadow SSDT hijack:

- no global dispatch patch,
- no Win32k/shadow SSDT dependence,
- no arbitrary code execution,
- no kCFG target issue,
- no CET return issue,
- lower PatchGuard pressure if restored quickly.

Remaining risks:

- `_EPROCESS` offset wrong,
- CR3 detection wrong,
- physical map returned bad/truncated user mapping,
- page crossing not handled,
- protected page under future KDP policy,
- token restore failed,
- driver blocked by WDAC/blocklist.

HVCI classification:

```text
HVCI-compatible data-only exploitation of unprotected mutable VTL0 data.
```

## 23. Case study: RTCore/dbutil-style virtual R/W

Virtual R/W driver class:

```text
driver copies to/from arbitrary kernel virtual address
```

Good strategy:

```text
1. Leak/obtain kernel module base and object addresses.
2. Validate offsets with reads.
3. Backup original target field.
4. Write minimal field.
5. Trigger desired normal Windows behavior.
6. Restore.
```

Why easier than physical R/W:

- no CR3 discovery,
- no page walker,
- no physical holes/MMIO,
- direct object semantics.

Why less low-level powerful:

- cannot naturally inspect arbitrary physical memory,
- cannot naturally recover from missing VA leaks,
- cannot easily reason about remapping/PTE unless PTE VA is known,
- still blocked by KDP-protected pages.

HVCI classification:

```text
Excellent for data-only targets.
Poor for trying to execute unsigned bytes.
```

## 24. Researcher's final mental model

When you have R/W, do not ask:

```text
How do I bypass HVCI?
```

Ask:

```text
What does HVCI actually stop in my intended chain?
```

Then map:

```text
Need unsigned code execution?
  HVCI directly relevant.

Need return-address ROP?
  CET directly relevant.

Need function pointer hijack?
  kCFG/XFG directly relevant.

Need to write selected policy/protected data?
  KDP directly relevant.

Need to load a known vulnerable driver?
  WDAC/blocklist directly relevant.

Need to write a mutable EPROCESS/KTHREAD field?
  HVCI often not the direct barrier.
```

The best "bypass" is often not a bypass at all. It is selecting a path where the mitigation was not designed to apply.

## 25. Sources

- Microsoft Learn - Enable memory integrity / HVCI: https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity
- Microsoft Security Blog - Kernel Data Protection: https://www.microsoft.com/en-us/security/blog/2020/07/08/introducing-kernel-data-protection-a-new-platform-security-technology-for-preventing-data-corruption/
- Microsoft Learn - Kernel-mode Hardware-enforced Stack Protection: https://learn.microsoft.com/en-us/windows-server/security/kernel-mode-hardware-stack-protection
- Microsoft Learn - Microsoft recommended driver block rules: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules
- Microsoft Support - Vulnerable driver blocklist after October 2022 preview release: https://support.microsoft.com/en-au/topic/kb5020779-the-vulnerable-driver-blocklist-after-the-october-2022-preview-release-3fcbe13a-6013-4118-b584-fcfbc6a09936
- Connor McGarr - HVCI/kCFG: https://connormcgarr.github.io/hvci/
- Connor McGarr - Paging: https://connormcgarr.github.io/paging/
- Satoshi Tanda - Intel VT-rp Part 1: https://tandasat.github.io/blog/2023/07/05/intel-vt-rp-part-1.html
- Satoshi Tanda - Intel VT-rp Part 2: https://tandasat.github.io/blog/2023/07/31/intel-vt-rp-part-2.html
- Fortinet - DSE tampering / KDP / page swapping: https://www.fortinet.com/blog/threat-research/driver-signature-enforcement-tampering
- Windows Internals - I/O Ring primitive research: https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/

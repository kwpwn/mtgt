# Connor McGarr HVCI/kCFG Deep Dive - Concept Explanations

Primary sources:

- Connor McGarr, "Exploit Development: No Code Execution? No Problem! Living The Age of VBS, HVCI, and Kernel CFG": https://connormcgarr.github.io/hvci/
- Microsoft KDP: https://www.microsoft.com/en-us/security/blog/2020/07/08/introducing-kernel-data-protection-a-new-platform-security-technology-for-preventing-data-corruption/
- Satoshi Tanda VT-rp Part 1/2: https://tandasat.github.io/blog/2023/07/05/intel-vt-rp-part-1.html and https://tandasat.github.io/blog/2023/07/31/intel-vt-rp-part-2.html

Goal of this document:

```text
Read Connor's post to the point of understanding:
- What HVCI blocks.
- Why old shellcode/PTE tricks are dead.
- Why data-only token swaps still work.
- Why token swaps are not powerful enough on their own.
- How to turn arbitrary R/W into kernel API invocation while staying "HVCI-compliant".
- How kCFG guards the forward edge.
- Why overwriting a return address sidesteps kCFG.
- Why kCET/shadow stack will kill this technique.
```

This document explains concepts and trade-offs. It is not an exploit runbook.

## 1. What question is Connor's post answering?

The central question:

```text
If HVCI no longer allows unsigned shellcode to run in the kernel,
what can an exploit writer do beyond token stealing?
```

Before HVCI:

```text
kernel bug -> arbitrary R/W -> control RIP -> shellcode -> call arbitrary kernel API
```

After HVCI:

```text
kernel bug -> arbitrary R/W -> cannot easily execute unsigned shellcode
```

Connor frames the problem:

```text
We do not run new shellcode.
We use code that already exists in the kernel.
We build a ROP chain to call legitimate kernel APIs.
```

This is not "disable HVCI." This is "living within HVCI's rules."

## 2. Why is token stealing the baseline?

Classic token stealing:

```text
current EPROCESS.Token = System EPROCESS.Token
```

Result:

```text
the current process becomes SYSTEM
```

Why it is popular:

- requires only a single pointer-sized write,
- no shellcode needed if you have an arbitrary write primitive,
- easy to verify,
- many LPE exploits only need SYSTEM.

But Connor argues that token stealing "undersells" the primitive.

Why?

Because kernel shellcode allows:

- calling kernel APIs,
- allocating pool,
- unloading a driver,
- creating a thread,
- disabling callbacks,
- executing arbitrary logic.

Token swap only gives:

```text
identity elevation
```

It does not give:

```text
arbitrary kernel function invocation
```

## 3. How does HVCI block shellcode?

HVCI uses Hyper-V/SLAT/EPT to enforce:

```text
kernel code pages: executable but not writable
kernel data pages: writable but not executable
```

It defeats the old pattern:

```text
allocate/write data page
mark executable
jump to shellcode
```

With HVCI:

- you cannot easily create a kernel RWX region,
- you cannot easily patch a code page,
- you cannot easily promote a data page to executable,
- you cannot easily run unsigned kernel code.

In table form:

| Old trick | HVCI response |
|---|---|
| write shellcode into pool | pool data not executable |
| patch kernel code | code page not writable at EPT |
| PTE mark data executable | EPT executable policy still wins |
| W+X page | HVCI/W^X tries to prevent |

## 4. Why is PTE manipulation not enough?

Without HVCI:

```text
PTE says page executable/writable -> CPU obeys guest PTE
```

With HVCI:

```text
guest PTE says executable
EPT/SLAT may still say not executable
```

Connor stresses "physical memory trumps virtual memory":

```text
PTE is VTL0's view.
EPTE is the hypervisor's view.
EPTE has the final say.
```

So if an attacker modifies a PTE to make a data page executable:

```text
guest PTE: X=1
EPT: X=0
=> execute fail
```

## 5. VBS and VTL: why the kernel is no longer the highest boundary

Before VBS:

```text
ring 0 kernel compromise = game over
```

After VBS:

```text
VTL0 normal kernel compromise != VTL1 secure kernel compromise
```

Connor explains:

- VTL0: normal kernel.
- VTL1: secure kernel.
- Hypervisor: a higher boundary that enforces memory views.

The secure kernel/VTL1 requests that the hypervisor set EPTE permissions for VTL0.

Key point:

```text
VTL1 is not the hypervisor.
VTL0 does not live inside VTL1.
VTL1 uses hypercalls to ask the hypervisor to configure VTL0.
```

## 6. What is a hypercall in this context?

A hypercall is like a syscall, but it calls into the hypervisor.

User/kernel code calls a syscall to enter the kernel.

The secure kernel calls a hypercall to ask the hypervisor to perform something more privileged:

```text
securekernel -> vmcall/hypercall -> hypervisor
```

In Connor's post:

- secure kernel code configures page protections,
- calls a hypercall wrapper,
- the hypervisor updates the EPT/SLAT view.

Why is this necessary?

```text
The secure kernel cannot modify the EPT directly like ordinary memory.
The EPT belongs to the hypervisor.
```

## 7. What is MBEC?

MBEC = Mode-Based Execute Control.

It lets an EPT entry distinguish execute permission by mode:

- execute for user mode,
- execute for supervisor/kernel mode.

Why does this matter?

SMEP blocks the kernel from executing user pages, but HVCI needs finer-grained execute permission management at the EPT layer.

If the CPU supports MBEC:

```text
the EPT can express: this user page is executable for user mode, not executable for kernel mode
```

This makes enforcement more efficient.

## 8. What is RUM?

RUM = Restricted User Mode.

If the CPU does not have MBEC, Windows uses a workaround:

```text
hypervisor maintains a second set of EPT
user pages marked non-executable for kernel
swap EPT view on transitions
```

Why is it slower?

- must switch EPT context/view,
- many user/kernel transitions,
- higher overhead than a direct MBEC bit.

A simple mnemonic:

```text
MBEC = one EPT view with smart bits.
RUM  = multiple EPT views to simulate those bits.
```

## 9. The new exploit problem: if shellcode is gone, how do you call kernel APIs?

Connor's goal:

```text
call arbitrary kernel API
```

without using:

```text
unsigned kernel shellcode
```

The idea:

```text
The kernel already contains valid code.
A ROP chain just chains together existing valid fragments.
```

For example, to call:

```text
nt!PsGetCurrentProcess()
```

Instead of writing shellcode that calls it:

```text
control the stack
set registers with gadgets
jump/return into the real function
capture the return value
exit the thread
```

## 10. Why do we need a "dummy thread"?

Connor creates a suspended thread.

Why?

- Each thread has its own kernel stack.
- If we corrupt the main thread's stack, the process may crash.
- The dummy thread is the sacrificial component.
- After the ROP completes, the dummy thread can be terminated.

Model:

```text
main exploit thread: in control, continues running
dummy suspended thread: has its kernel stack overwritten, runs ROP, then exits cleanly
```

This is reliability engineering for exploits.

## 11. Why does a suspended thread still have a useful kernel stack?

When a thread is created, it goes through the kernel startup path.

Being suspended does not mean "no kernel state." It has:

- ETHREAD/KTHREAD,
- a kernel stack,
- a call stack related to startup/APC,
- return addresses.

Connor leaks the `KTHREAD`, then from it reads `StackBase`.

Because the ROP chain needs somewhere to write:

```text
return address + fake stack frames + gadgets + arguments
```

## 12. Leaking KTHREAD with `NtQuerySystemInformation`

Connor uses `NtQuerySystemInformation(SystemHandleInformation)` to leak the kernel object pointer for the dummy thread handle.

Concept:

```text
the user process holds a handle to the dummy thread
SystemHandleInformation reveals the object pointer associated with the handle
that object is the ETHREAD/KTHREAD-related kernel object
```

Why is this needed?

To modify the kernel stack, you must know:

```text
the KTHREAD address
KTHREAD.StackBase
```

Without the leak:

```text
an arbitrary write has nowhere meaningful to target
```

## 13. Why not just token swap?

Token swap:

```text
get SYSTEM
```

Kernel API invocation:

```text
call any kernel API
```

Examples of the broader capability:

- allocate/free pool,
- query/modify kernel objects,
- call `Ps*`, `Zw*`, `Mm*`,
- cleanly terminate a thread,
- chain multiple operations.

Connor wants a primitive equivalent to shellcode in capability, but without violating HVCI.

## 14. What is kCFG?

kCFG = kernel Control Flow Guard.

CFG protects forward-edge indirect calls:

```text
call [function_pointer]
jmp [register]
```

It checks whether the target is present in the valid call-target bitmap.

In the kernel, the kCFG bitmap is protected by HVCI/SLAT, so an attacker with arbitrary R/W cannot easily modify it.

If an attacker overwrites a function pointer:

```text
indirect call -> kCFG checks target
invalid -> fail
```

## 15. Why is overwriting a function pointer no longer effective?

Before kCFG:

```text
overwrite HalDispatchTable/callback/function pointer -> jump to shellcode/gadget
```

After kCFG:

```text
indirect call target must be valid
```

If the target is invalid:

- crash,
- fast fail,
- no control.

Because the kCFG bitmap is protected by HVCI, an attacker cannot simply set a bit to authorize an arbitrary target.

## 16. Why does a return address sidestep kCFG?

kCFG primarily protects the forward edge:

- indirect calls,
- indirect jumps.

A return address is the backward edge:

```text
ret
```

Classic CFG does not check every return.

Therefore:

```text
overwrite return address -> ROP chain
```

is not blocked by kCFG in the same way.

This is why Connor targets a stack return address instead of a function pointer.

## 17. Why will kCET break this technique?

kCET/kernel CET shadow stack protects return addresses.

The CET shadow stack maintains a separate, more-protected copy of return addresses.

When `ret` executes:

```text
the normal-stack return address must match the shadow-stack return address
```

If an attacker only modifies the normal stack:

```text
mismatch -> control protection fault / bugcheck
```

Connor explicitly notes that the ROP-via-return-address technique will be obsolete once kCET is mainstream.

## 18. Why is a ROP chain still "HVCI-compliant"?

HVCI blocks:

```text
executing unsigned code
```

A ROP chain uses:

```text
code already present in signed kernel images
```

No new executable page is created.

No unsigned shellcode is involved.

From HVCI's perspective:

```text
the CPU is executing legitimate kernel code pages
```

Therefore it is "compliant" with HVCI, despite the malicious intent.

## 19. Is ROP affected by SMEP/SMAP?

SMEP:

- blocks the kernel from executing user pages.
- ROP uses kernel gadgets; it does not execute user pages.

SMAP:

- blocks kernel access to user pages in certain contexts.
- Connor notes that Windows only uses SMAP in specific situations, particularly at IRQL >= DISPATCH_LEVEL.
- If the chain runs at IRQL 0/PASSIVE_LEVEL, some data movement to user addresses may not be blocked by SMAP.

Why does IRQL matter?

- Many kernel APIs are only valid at PASSIVE_LEVEL.
- The APC/dummy-thread path provides a more appropriate context compared to an arbitrary interrupt/DPC.

## 20. What is IRQL?

IRQL = Interrupt Request Level.

It determines:

- what can interrupt what,
- which code is allowed to run,
- whether page faults are permitted,
- whether blocking APIs may be called.

Common levels:

| IRQL | Meaning |
|---|---|
| PASSIVE_LEVEL = 0 | normal kernel/user work, most APIs callable |
| APC_LEVEL = 1 | APC processing |
| DISPATCH_LEVEL = 2 | DPC/spinlock context, more restricted |

A ROP chain that calls arbitrary kernel APIs generally needs PASSIVE_LEVEL. Calling an API at the wrong IRQL will likely BSOD the machine.

## 21. Why does 16-byte stack alignment matter?

The Windows x64 calling convention requires a specific stack alignment, typically 16 bytes before a call.

Many kernel/user APIs use XMM/SIMD instructions or have prologues that assume alignment.

If a ROP chain calls a function with a misaligned stack:

- crash,
- memory access fault,
- undefined behavior.

Connor uses an extra `ret` to adjust alignment before entering `ZwTerminateThread`.

This is a small detail but critical for exploit reliability.

## 22. What to remember about the x64 calling convention?

Windows x64:

```text
arg1 -> RCX
arg2 -> RDX
arg3 -> R8
arg4 -> R9
extra args -> stack
return value -> RAX
```

Therefore the ROP chain needs gadgets to:

- set RCX,
- set RDX,
- set R8/R9 if needed,
- set RAX to the function target,
- jump/call the function,
- handle the return value.

If the function takes no arguments (like `PsGetCurrentProcess`), the chain is much simpler.

## 23. Why use `PsGetCurrentProcess` as a demo?

It is a simple kernel API:

- no parameters required,
- returns a `PEPROCESS`,
- easy to verify,
- no dangerous side effects.

It proves:

```text
the ROP chain can call a kernel API and capture the return value
```

before attempting more complex APIs.

## 24. Why do we need to save the return value back to user mode?

The ROP chain runs in the kernel context of the dummy thread.

After calling `PsGetCurrentProcess`, the return value is in RAX.

If RAX is not saved somewhere:

```text
the main exploit thread cannot retrieve the result
```

Connor uses a gadget of the form:

```text
mov [rcx], rax
```

with RCX pointing to a user-mode buffer.

That is the "return channel" from the kernel ROP back to the user-mode controller.

## 25. Why can we write to a user buffer?

In the demo, the chain runs at low IRQL, and per Connor's observation SMAP does not interfere in that context.

However, this is version- and configuration-dependent.

Safer conceptual alternatives:

- write the return value into a kernel buffer and read it back via an arbitrary read,
- or use a legitimate existing copy-to-user API.

Trade-off:

- a user buffer is simpler,
- a kernel buffer is less dependent on SMAP but requires additional management.

## 26. Why end with `ZwTerminateThread`?

The ROP chain has corrupted the stack and register state of the dummy thread.

Cleanly restoring everything is very difficult.

Instead of restoring:

```text
call ZwTerminateThread(dummy_thread, STATUS_SUCCESS)
```

Rationale:

- the dummy thread is disposable,
- the main thread remains alive,
- Windows cleans up the thread state, avoiding a crash from a corrupted return path.

This reflects good exploit engineering thinking:

```text
don't try to restore something complex when a legitimate API can dispose of it
```

## 27. Why must the dummy thread be a separate thread?

If ROP runs on the main thread:

- the main thread stack is corrupted,
- the exploit controller loses control,
- the process may crash,
- cleanup is difficult.

The dummy thread:

- has its own stack,
- has its own KTHREAD,
- has its own handle,
- can be terminated independently.

It acts as a small sandbox for the kernel ROP.

## 28. Connor's chain summarized as pseudo-flow

No exploit code, just the flow:

```text
1. Obtain an arbitrary kernel read/write primitive.
2. Create a suspended dummy thread.
3. Leak the dummy thread's KTHREAD via handle information.
4. Leak KTHREAD.StackBase.
5. Read the dummy thread's kernel stack.
6. Locate a suitable return address.
7. Write the ROP chain onto the stack.
8. The chain sets registers per the Windows x64 ABI.
9. The chain calls a legitimate kernel API.
10. The chain saves the return value.
11. The chain calls ZwTerminateThread to exit.
12. Resume the dummy thread.
13. The main thread reads the result.
```

## 29. Why is this not an "HVCI bypass" in the vulnerability sense?

Connor emphasizes:

```text
HVCI itself is not exploited by a bug.
```

HVCI promises:

```text
no unsigned kernel code will execute
```

The ROP chain:

```text
executes signed, existing kernel code
```

So HVCI is still doing its job correctly.

The exploit merely shifts its goal:

```text
shellcode is unnecessary if you can chain existing kernel code
```

This is a tactical bypass of shellcode dependency, not a vulnerability bypass of HVCI itself.

## 30. Which mitigations block this chain?

HVCI:

- blocks shellcode and PTE-executable tricks.
- does not block return-oriented reuse of existing code.

kCFG:

- blocks forward-edge indirect call targets.
- does not block return addresses.

kCET/shadow stack:

- blocks return address corruption.
- this is the most direct mitigation.

PatchGuard:

- does not necessarily block a short-lived stack ROP.
- blocks persistent global kernel patches.

SMEP:

- not relevant when gadgets are in kernel space.

SMAP:

- may affect user-buffer access depending on IRQL/config.

## 31. Relationship to VT-rp Part 2

VT-rp Part 2 discusses:

- PW/PWA providing effective protection of paging structures.
- GPV blocking aliasing/remapping paths.

Connor discusses:

- if shellcode cannot execute because of HVCI,
- use ROP over existing kernel code.

The two topics operate at different layers:

| Topic | Layer |
|---|---|
| VT-rp/HLAT/GPV | protecting the translation/page-table path |
| HVCI/kCFG/CET | protecting code execution / control-flow path |
| Connor ROP | exploit technique that lives in the HVCI/kCFG gap |

Combined:

```text
HVCI blocks shellcode.
kCFG blocks arbitrary indirect call targets (forward edge).
kCET blocks return-address ROP.
VT-rp blocks page-table remapping.
```

Exploit writers are pushed toward data-only approaches or other logic bugs.

## 32. Important "why" questions

### Why not patch the kCFG bitmap?

Because HVCI/SLAT protects it. The guest PTE may say writable, but the EPT has the final say.

### Why not overwrite a function pointer?

Because kCFG checks the indirect call target.

### Why overwrite a return address?

Because kCFG does not check the backward-edge return.

### Why will this technique die with kCET?

Because the shadow stack detects when the return address on the normal stack has been modified.

### Why is shellcode unnecessary?

Because ROP reuses existing code.

### Why a dummy thread?

Because it provides a disposable execution context.

### Why must KTHREAD be leaked?

Because you need to know which thread's kernel stack to write the ROP chain to.

### Why are both arbitrary read and write required?

Read to leak stack/addresses and validate. Write to plant the chain.

### Why the kernel stack rather than the user stack?

ROP runs while the thread is on a kernel code path; the return addresses are on the kernel stack.

### Why call `ZwTerminateThread`?

Because cleanly restoring the stack and registers is very difficult, and terminating a disposable thread is far simpler.

## 33. Common BSOD points

| Point | Why it crashes |
|---|---|
| Wrong KTHREAD | writes to wrong kernel memory |
| Wrong StackBase | read/write hits wrong page |
| Wrong return address | control flow jumps to garbage |
| Bad gadget | corrupts registers/stack |
| Misaligned stack | API prologue/XMM fault |
| API called at wrong IRQL | kernel bugcheck |
| User buffer access blocked by SMAP/config | fault |
| Thread not terminated or restored | return path is corrupt |
| kCET enabled | shadow stack mismatch |

## 34. Why is this post exceptionally valuable?

Because it teaches a critically important pattern:

```text
When code injection dies, invocation of existing code becomes the goal.
```

It also demonstrates that modern exploits are not just:

```text
write what where -> token steal
```

but rather:

```text
build a reliable execution model under mitigations
```

The right questions are not:

- "How do I disable HVCI?"

But:

- "What exactly does HVCI block?"
- "What does it not block?"
- "Does kCFG protect the forward edge or the backward edge?"
- "Is CET already enabled?"
- "Can I reuse existing signed kernel code?"
- "Do I have a disposable kernel context?"

## 35. Relationship to ASTRA64 direct DKOM

ASTRA direct DKOM:

```text
physical R/W -> one data write -> SYSTEM
```

Connor's chain:

```text
arbitrary R/W -> stack ROP -> arbitrary kernel API invocation
```

ASTRA direct DKOM is the right tool when:

- the goal is only SYSTEM privilege,
- the token field is writable,
- offsets are correct.

Connor's chain is the right tool when:

- kernel API calls are required,
- a token swap is insufficient,
- you want to emulate shellcode capability.

But Connor's chain is more fragile:

- ROP,
- stack,
- return address,
- kCET,
- alignment,
- IRQL.

## 36. Relationship to AsIO3 PreviousMode

AsIO3:

```text
flip PreviousMode -> use NtRead/NtWrite as kernel R/W
```

Connor:

```text
arbitrary R/W -> use dummy thread stack ROP -> call APIs
```

Both avoid shellcode.

The difference:

- AsIO3 turns syscall APIs into a memory R/W primitive.
- Connor turns R/W into an arbitrary kernel API call primitive.

One is:

```text
API boundary confusion
```

The other is:

```text
control-flow reuse under HVCI
```

## 37. If kCET is enabled, what remains?

If kCET shadow stack is truly enforced:

- return-address ROP becomes extremely difficult.

Exploits must pivot to:

- data-only attacks,
- logic bugs,
- valid indirect call targets,
- callback/object state abuse,
- call-oriented programming via legitimate dispatch if kCFG permits,
- corrupting arguments/state rather than return addresses,
- exploiting bugs in trusted code paths.

This is why modern exploits are increasingly data-oriented.

## 38. How to study Connor's post

Read in order:

1. Token stealing baseline.
2. HVCI/SLAT/VBS.
3. MBEC/RUM.
4. kCFG bitmap and forward edge.
5. Why return addresses sidestep kCFG.
6. Dummy thread / KTHREAD leak.
7. Kernel stack anatomy.
8. Windows x64 calling convention.
9. ROP chain as API invocation.
10. Cleanup via thread termination.
11. kCET as a future blocker.

If any step is unclear, return to the concept level:

- "Which address do I need right now?"
- "Which memory am I writing to?"
- "Which mitigation is guarding which edge?"
- "Which code is executing: unsigned new code or signed existing code?"

## 39. Glossary

| Term | Meaning |
|---|---|
| HVCI | Hypervisor-protected Code Integrity |
| VBS | Virtualization-Based Security |
| VTL0 | normal kernel world |
| VTL1 | secure kernel world |
| SLAT/EPT | second-level address translation, hypervisor memory permissions |
| EPTE | EPT entry |
| MBEC | mode-based execute control |
| RUM | restricted user mode |
| kCFG | kernel Control Flow Guard |
| kCET | kernel Control-flow Enforcement Technology |
| Shadow stack | protected return-address stack |
| KTHREAD | kernel thread object |
| Kernel stack | per-thread stack used in kernel mode |
| IRQL | interrupt request level |
| ROP | return-oriented programming |
| Forward-edge | indirect call/jump |
| Backward-edge | return |

## 40. Conclusion

Connor's post carries a clear message:

```text
HVCI kills shellcode, not every form of arbitrary R/W exploitation.
```

When shellcode is dead, exploits shift to:

```text
data-only
existing-code invocation
ROP/call-oriented primitives
semantic field corruption
```

kCFG kills many function-pointer hijacks, but return-address ROP remains viable as long as kCET is not enabled.

VT-rp/HLAT/GPV operate in a different direction: they protect the translation path and page-table tricks.

The combined pressure of modern mitigations:

```text
HVCI  -> no unsigned kernel code
kCFG  -> no arbitrary indirect call target
kCET  -> no return-address ROP
KDP   -> no direct write to protected data
VT-rp -> no remapping protected LA
```

Modern exploit development must therefore continuously ask:

```text
What exactly does this mitigation protect?
What falls outside its scope?
Which edge does my primitive target?
Is there a data-only path to reach the goal?
Is true code execution actually required?
```

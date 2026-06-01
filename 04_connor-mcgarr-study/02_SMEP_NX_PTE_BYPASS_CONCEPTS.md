# 02 - SMEP, NX, PTE Bypass Concepts

Based on Connor McGarr:

- https://connormcgarr.github.io/x64-Kernel-Shellcode-Revisited-and-SMEP-Bypass/
- https://connormcgarr.github.io/paging/
- https://connormcgarr.github.io/hvci/

Last updated: 2026-05-25

## 1. Problem statement

Old kernel exploit chain:

```text
control RIP in kernel
  -> jump to user-mode shellcode
  -> steal SYSTEM token
```

This died because of:

- NX/DEP: data pages are not executable.
- SMEP: kernel cannot execute user pages.
- HVCI: changing the guest PTE does not necessarily make a page executable under hypervisor-enforced code integrity.
- CET/shadow stack: return-address ROP becomes harder when enabled.

Connor's SMEP article is useful because it sits at the transition point: old x64 kernel shellcode still works in concept, but SMEP forces you to understand page permissions and CPU control bits.

## 2. NX: "can this page be fetched as instructions?"

NX is execute permission. If NX is set, the CPU should not fetch instructions from that page.

Exploit impact:

- Stack shellcode fails.
- Heap/pool shellcode fails.
- User page shellcode fails unless the page is executable.

Bypass classes:

- Reuse executable code: ROP/JOP/COP.
- Modify page permissions if the primitive allows.
- Use a data-only attack.
- Use an existing kernel API/code path instead of injecting code.

Windows-current view:

- Without HVCI, PTE permission tampering may work in a lab.
- With HVCI, the guest PTE permission is not sufficient for kernel executable status.

## 3. SMEP: "is supervisor executing a user page?"

SMEP checks the U/S bit during instruction fetch while CPL=0. If kernel mode tries to fetch from a page marked user, the CPU faults.

It specifically kills:

```text
kernel RIP -> user VA payload
```

It does not kill:

- Kernel ROP using kernel executable pages.
- Data-only writes.
- Token DKOM.
- Process-kill driver IOCTL.
- Existing signed code invocation.

## 4. Why PTE bit flipping was attractive

The obvious thought:

```text
If SMEP hates user pages, clear U/S bit.
If NX hates non-executable pages, clear NX bit.
```

This turns the page, from the attacker's perspective, into:

```text
supervisor + executable
```

Historically, with a strong arbitrary write, this could convert user shellcode into something the kernel can fetch.

## 5. Why this is not the best modern plan

On Windows 11 with HVCI:

```text
Guest PTE says executable
  !=
Hypervisor says executable
```

HVCI can enforce that kernel executable pages correspond to trusted/signed code. A user page whose PTE was modified does not magically become trusted kernel code.

So the modern question becomes:

```text
Can I achieve the goal without executing my own bytes?
```

Usually better:

- data-only token/object change,
- existing signed kernel code invocation,
- legitimate driver IOCTL semantics,
- process-kill primitive if the goal is defensive bypass in a lab.

## 6. CR4 SMEP disable: why it is unstable

Another classic route:

```text
ROP -> write CR4 with SMEP bit cleared -> execute user payload -> restore
```

Why fragile:

- Requires kernel base leak.
- Requires suitable gadgets.
- Requires stack control.
- Requires no CET/shadow stack enforcement.
- Requires concurrency care: disabling SMEP is CPU/core state sensitive.
- Requires restore.
- HVCI may still block unsigned kernel code execution.

This route is a good teaching device, not the default stable route on current Windows.

## 7. Data-only bypass mindset

Instead of:

```text
defeat SMEP so I can run shellcode
```

Ask:

```text
what final data state would shellcode create?
can my primitive directly create that data state?
```

For token stealing:

```text
Shellcode would copy the SYSTEM token.
Arbitrary write can copy/write the SYSTEM token directly.
```

For `PreviousMode` abuse:

```text
Shellcode would get kernel read/write.
A limited write can change PreviousMode so normal syscalls behave differently.
```

For process termination:

```text
Shellcode would call PsTerminateProcess.
Process-kill BYOVD can do it as driver functionality.
```

## 8. Research checklist

When reading any SMEP bypass:

- Is SMEP actually enabled?
- Is HVCI enabled?
- Is CET kernel shadow stack enabled?
- Does the chain require executing attacker bytes?
- Is the page user or supervisor after modification?
- Is the page trusted executable under HVCI?
- Is the bypass global or per-page?
- Is restore required?
- Could the same goal be done data-only?

## 9. Takeaway

SMEP/NX bypasses teach CPU/page-table mechanics. On current Windows, the stronger exploit engineering lesson is not "how to force shellcode to execute", but "how to avoid needing shellcode at all."

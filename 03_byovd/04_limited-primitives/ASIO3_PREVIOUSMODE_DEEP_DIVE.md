# ASUS AsIO3.sys / CVE-2025-3464 PreviousMode Deep Dive

Sources:

- jeffaf exploit repo: https://github.com/jeffaf/CVE-2025-3464-AsIO3-LPE
- BackBox mirror of Talos-style write-up: https://news.backbox.org/2025/06/26/decrement-by-one-to-rule-them-all-asio3-sys-driver-exploitation/
- CVE summary: https://vulmon.com/vulnerabilitydetails?qid=CVE-2025-3464

This case is not a physical-memory BYOVD like ASTRA64. It is more subtle:

```text
auth bypass
  -> limited arithmetic primitive
  -> KTHREAD.PreviousMode flip
  -> legitimate NtRead/NtWrite APIs become kernel memory R/W
  -> EPROCESS token theft
```

It is a good example of a weak primitive becoming powerful by targeting the right one-byte kernel field.

## 1. What Makes AsIO3 Different

ASTRA/ThrottleStop/eneio64:

- expose physical memory access,
- require VA->PA translation,
- use direct physical writes.

AsIO3:

- has an authentication gate,
- exposes a decrement-like primitive through `ObfDereferenceObject` misuse,
- targets `KTHREAD.PreviousMode`,
- then abuses normal NT memory APIs to read/write kernel memory.

This is a different exploit philosophy:

```text
do not need broad physical R/W if one small write flips a boundary flag
```

## 2. The Auth Bypass: Why TOCTOU Matters

The driver tries to restrict access to ASUS trusted components.

Public repos describe a check like:

- process path contains `AsusCertService`,
- hash verification against ASUS service binary,
- device open authorized after that check.

The flaw is TOCTOU:

```text
time of check: path/hardlink points to expected ASUS file
time of use: attacker-controlled process gets authorized handle
```

Why this matters:

- The driver has a security boundary before dangerous IOCTLs.
- If the boundary is bypassed, low-privileged code reaches privileged driver functionality.
- The memory primitive does not matter unless the caller can open/use the device.

This is a common pattern in BYOVD:

```text
vendor added auth, but implemented it with path/string/race assumptions
```

## 3. Why Hardlinks Are Useful in the Bypass

NTFS hardlinks let two paths refer to the same file record. If a driver/service validates by path or opens/checks by one path while execution identity changes, a race can appear.

The public technique:

- create path containing trusted ASUS service string,
- make it point to attacker-controlled executable,
- spawn process so image path passes substring check,
- race/swap link to real ASUS binary for hash validation,
- obtain driver access.

Why this works conceptually:

- path identity and file identity are not the same thing,
- string contains checks are weak,
- time-separated validation can be raced.

Defensive lesson:

- kernel authorization should not trust mutable user-writable paths.
- use signed service mediation, secure handles, strong ACLs, and stable file identity checks.

## 4. The Primitive: Decrement Through `ObfDereferenceObject`

The public repo describes an IOCTL where the driver calls `ObfDereferenceObject` on a user-controlled pointer.

`ObfDereferenceObject(ptr)` effectively decrements an object reference count at a fixed negative offset from the object pointer.

If attacker controls `ptr`, the effect becomes:

```text
decrement 8-byte value at attacker-chosen-address-minus-constant
```

This is not arbitrary write. It is an arithmetic primitive:

```text
target_value = target_value - 1
```

Why this is weaker than arbitrary write:

- You cannot write any value.
- You can only decrement.
- Alignment and target address constraints matter.

Why it is still powerful:

- Some kernel fields become exploitable when decremented from 1 to 0.
- `PreviousMode` is exactly such a field.

## 5. Why `PreviousMode` Is the Perfect Target

`KTHREAD.PreviousMode` tells kernel routines whether the caller came from user mode or kernel mode.

Typical values:

```text
UserMode   = 1
KernelMode = 0
```

If an attacker decrements `PreviousMode` from 1 to 0:

```text
kernel APIs believe the current thread is a kernel caller
```

Why this is powerful:

- `NtReadVirtualMemory` / `NtWriteVirtualMemory` and similar paths apply probing/access checks based on previous mode.
- With `PreviousMode = KernelMode`, some user-supplied pointers/addresses are treated more trustingly.
- This can turn normal syscalls into kernel memory read/write tools.

This is a classic "small field, huge boundary" target.

## 6. Why This Beats Searching for Arbitrary R/W

The decrement primitive is weak. But targeting `PreviousMode` makes it enough.

Alternative:

- Try to build arbitrary write by repeated decrements.
- Search for a function pointer whose value can be decremented into a useful pointer.
- Use decrement on reference counts for UAF.

Chosen route:

- decrement one byte/field from 1 to 0.

Why chosen route is better:

- minimal primitive requirement,
- no need to set arbitrary value,
- no shellcode,
- no physical memory translation,
- no page-table modification,
- no MSR or code execution.

The exploit power comes from field semantics, not primitive strength.

## 7. How It Becomes Kernel R/W

After `PreviousMode` is flipped, the process can use legitimate system calls to read/write kernel addresses.

Conceptual route:

```text
leak KTHREAD/current thread address
decrement PreviousMode
use NtReadVirtualMemory/NtWriteVirtualMemory on kernel addresses
walk EPROCESS list
copy SYSTEM token
restore PreviousMode
spawn shell
```

The key is that the kernel's own memory-copy path is doing the access under a mistaken caller mode.

This is cleaner than direct arbitrary write because it reuses existing kernel APIs.

## 8. Why Restoring PreviousMode Is Critical

Public notes emphasize restoring `PreviousMode` before process creation.

Why:

- Many syscalls expect user-mode callers to have `PreviousMode = UserMode`.
- If it remains KernelMode while user-mode APIs pass user pointers, kernel code may skip probes and treat invalid user pointers as trusted kernel pointers.
- This can trigger bugchecks such as `PREVIOUS_MODE_MISMATCH` or crashes in process creation paths.

So the exploit must:

```text
flip PreviousMode to 0
perform kernel R/W
restore PreviousMode to 1
continue user-mode operations
```

This is the main stability rule.

## 9. Windows Version Stability

Public repo notes:

- tested on Windows 11 22H2 / build 22621,
- Windows 23H2+ has mitigations against PreviousMode abuse in some paths,
- specific offsets are version-sensitive.

Version-sensitive fields:

- `KTHREAD.PreviousMode`,
- `KTHREAD.Process`,
- `_EPROCESS.UniqueProcessId`,
- `_EPROCESS.ActiveProcessLinks`,
- `_EPROCESS.Token`.

Why this is less stable today:

- Microsoft is aware of PreviousMode tricks.
- Newer builds add checks/bugchecks for inconsistent caller mode behavior.
- Offsets change.

Compared with ASTRA direct DKOM:

- AsIO3 avoids physical translation.
- But PreviousMode abuse is more specifically mitigated on newer Windows.

## 10. BSOD Risk Matrix

| Stage | Risk | Why |
|---|---|---|
| Auth race | Low | Usually just access fail. |
| Wrong decrement target | High | Corrupts arbitrary kernel data by -1. |
| PreviousMode flip | Medium | Safe only if exact field/byte behavior correct. |
| Kernel read/write APIs while flipped | Medium-high | Wrong pointers or new mitigations can bugcheck. |
| Forget restore | High | User-mode syscalls can crash later. |
| Token write | Medium | Offset-sensitive. |
| Newer Windows 23H2+ | High | PreviousMode mismatch mitigations. |

## 11. Why This Technique Is Elegant

It shows a key exploit engineering principle:

```text
a weak primitive can be enough if it targets the right semantic bit
```

The decrement primitive is not impressive alone. But `PreviousMode` is a privileged boundary switch.

The technique avoids:

- shellcode,
- PTE patch,
- physical memory scan,
- MSR write,
- Win32k dispatch hijack.

The cost:

- narrow version support,
- fragile restore requirement,
- strong dependency on exact thread offsets.

## 12. Defensive Takeaways

Detect/prevent:

- vulnerable AsIO3 driver versions,
- user-writable paths containing trusted service substrings,
- hardlink activity around trusted ASUS service names,
- non-ASUS processes opening `Asusgio3` device,
- driver loads from Armoury Crate components on unneeded systems,
- WDAC block of vulnerable versions.

Design lessons:

- Do not authorize driver callers using mutable path strings.
- Do not expose object-reference primitives to user-controlled pointers.
- Validate caller identity and target object class.

## 13. Final Takeaway

AsIO3 is not a "big primitive" exploit. It is a "right field" exploit.

The chain succeeds because:

```text
decrement primitive + PreviousMode 1->0 = kernel APIs become memory R/W
```

That makes it a very useful study case for why exploitability is not only about arbitrary write. Sometimes a one-byte semantic flip is enough.


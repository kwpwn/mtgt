# New BYOVD Driver Reversing Workflow

This workflow is for analyzing a new driver and writing a deep-dive like the files in this folder.

Related technique references:

- `IOCTL_BUG_CLASS_PLAYBOOK.md`
- `..\..\docs\kernel-research\driver-exploit-technique-atlas.md`
- `..\..\docs\detection-and-mitigation\driver-evasion-pressure-map.md`

## 1. Identify the Driver

Collect:

- filename,
- service name,
- device object,
- symbolic link,
- signer,
- certificate chain,
- hashes,
- version resource,
- product/vendor,
- known CVE/LOLDrivers status.

Do not rely on filename alone. BYOVD tooling often renames drivers.

## 2. Determine Load Model

Questions:

- Is it already installed on target systems?
- Can low-priv users access it if installed?
- Does the attacker need admin to load it?
- Is it boot-start/system-start/demand-start?
- Is it HVCI-compatible?
- Is it blocklisted?

This tells you whether the case is:

- local low-priv LPE,
- admin-to-kernel BYOVD,
- defense evasion,
- DoS only.

## 3. Find Device Creation

In IDA/Ghidra:

- locate `DriverEntry`,
- find `IoCreateDevice`,
- find `IoCreateSymbolicLink`,
- inspect SDDL if using secure device creation,
- inspect major function table.

Important functions:

- `IoCreateDevice`
- `IoCreateDeviceSecure`
- `IoCreateSymbolicLink`
- `WdfDeviceCreate`
- `WdfIoQueueCreate`

## 4. Locate IOCTL Dispatch

For WDM:

- find `IRP_MJ_DEVICE_CONTROL` handler.

For WDF:

- find queue callbacks.

Extract:

- IOCTL codes,
- method,
- access bits,
- input/output buffer usage,
- expected sizes,
- switch/case logic,
- subcommands.

## 5. Classify Primitive

Common classes:

- physical memory R/W,
- virtual kernel R/W,
- MSR read/write,
- port I/O,
- PCI config access,
- process kill,
- thread kill,
- file/registry protection modification,
- callback tamper,
- object handle operation,
- limited arithmetic/write primitive,
- info leak only,
- DoS only.

## 6. Check Access Control

Questions:

- Who can open the device?
- Does IOCTL require admin?
- Does driver check caller process?
- Does it use path/signer checks?
- Are those checks bypassable through hardlinks, hollowing, injection or handle duplication?
- Does a trusted service broker expose the handle?

Access control is often the real vulnerability.

## 7. Inspect Buffer Handling

Look for:

- `METHOD_NEITHER`,
- raw user pointers,
- missing length checks,
- integer overflow,
- pointer truncation,
- same buffer input/output,
- struct version mismatch,
- kernel pointer from user buffer,
- unchecked physical address.

## 8. Dangerous API Map

Flag calls to:

- `MmMapIoSpace`,
- `MmCopyMemory`,
- `MmMapLockedPagesSpecifyCache`,
- `IoAllocateMdl`,
- `MmProbeAndLockPages`,
- `ZwOpenSection` on `\Device\PhysicalMemory`,
- `__readmsr` / `__writemsr`,
- `READ_PORT_*` / `WRITE_PORT_*`,
- `ZwOpenProcess`,
- `ZwTerminateProcess`,
- `ObReferenceObjectByHandle`,
- `ObfDereferenceObject`,
- `PsLookupProcessByProcessId`,
- `ZwQuerySystemInformation(SystemModuleInformation)`.

## 9. Decide Best-Fit Exploit Path

Use the matrix:

| Primitive | Best path |
|---|---|
| physical R/W | VA->PA bridge + data-only write |
| virtual R/W | direct token/PPL/object write |
| MSR only | leak or syscall hijack research; expect fragility |
| process kill | use as process killer, do not overcomplicate |
| decrement/add primitive | target semantic fields like `PreviousMode` |
| file/registry operation | look for LPE via privileged file/registry abuse |

Do not force every driver into token stealing.

## 10. Analyze Stability

For each technique, document:

- Windows version dependency,
- driver version dependency,
- offset dependency,
- HVCI/VBS dependency,
- blocklist dependency,
- BSOD risk,
- detection surface,
- cleanup/restore behavior.

## 11. Write the Deep-Dive

Use this section template:

```text
1. Driver role
2. Primitive overview
3. Access control / auth gate
4. Why this primitive matters
5. Why this exploit path is chosen
6. Alternatives and why they are worse/better
7. Stability across Windows versions
8. Stability across driver versions
9. BSOD risk matrix
10. Defensive view
11. Final takeaway
```

## 12. Safety Boundary

For documentation:

- explain concepts,
- explain trade-offs,
- explain failure modes,
- avoid publishing fresh weaponized payloads for unknown/unfixed issues,
- avoid exact packet construction for unpatched zero-days unless already public and appropriate for your lab.

The goal is to understand and defend, not to create turnkey abuse.

# Device ACL, SDDL, and IOCTL Access

Updated: 2026-05-27

## Purpose

This note explains the reachability layer that sits before every driver primitive:

```text
can the caller open the device,
and can the caller send the dangerous IOCTL?
```

For BYOVD and driver exploit research, this is as important as memory corruption. A driver with a strong primitive but a tight device ACL may be less reachable than a weaker primitive exposed to every local user.

Safety boundary:

- no exploit code,
- no IOCTL recipes,
- no weaponized driver access steps,
- focus on access-control reasoning and defensive review.

## Core Model

Driver reachability is a chain:

```text
driver loads
  -> device object exists
  -> symbolic link or interface is discoverable
  -> caller can open it with desired access
  -> IOCTL access bits permit the request
  -> driver-specific auth permits the operation
```

If any link fails, the primitive is not reachable from that caller.

## Device Object Security

Windows controls access to named device objects using security descriptors and ACLs. Depending on the driver model, security can come from:

- device object creation,
- INF or registry security descriptor,
- setup class policy,
- `IoCreateDeviceSecure`,
- WDF device initialization,
- default device type policy.

Why:

```text
the I/O manager enforces device object access before the driver's IOCTL code runs
```

This means a write primitive in a handler is not automatically reachable by low-privilege users. The open path decides the first boundary.

## `IoCreateDevice` Versus `IoCreateDeviceSecure`

### `IoCreateDevice`

Classic driver code may call `IoCreateDevice`.

Key review points:

- Is the device named?
- Which `DeviceType` is used?
- Are device characteristics correct?
- Is `FILE_DEVICE_SECURE_OPEN` set?
- Is security inherited from PnP/device-class policy?

Microsoft notes that most drivers specify `FILE_DEVICE_SECURE_OPEN`.

### `IoCreateDeviceSecure`

Non-WDM drivers that create named device objects should use `IoCreateDeviceSecure` with a security descriptor and class GUID.

Review questions:

- Is there a custom SDDL string?
- Does it allow `WD` or `BU` broad access?
- Does it restrict to `SY` and `BA`?
- Does it grant read-only, write-only, or all access?
- Does registry policy override the default descriptor?

Why:

```text
IoCreateDeviceSecure makes reachability explicit;
IoCreateDevice plus default or inherited policy often requires more context
```

## SDDL Review

SDDL is a compact string representation of a security descriptor.

Common review concepts:

| Token concept | Meaning in review |
|---|---|
| `SY` | LocalSystem |
| `BA` | Built-in Administrators |
| `BU` | Built-in Users |
| `WD` | Everyone |
| generic all | full device access |
| generic read/write | open handle with specific desired rights |

Do not judge only by the presence of `BA` or `SY`. Ask what access is granted and whether any broad group can open the device.

Reachability categories:

| Category | Meaning |
|---|---|
| kernel only / system only | not directly reachable by ordinary userland |
| administrators only | admin-to-kernel BYOVD/evasion scenario |
| built-in users | local user-to-driver attack surface |
| everyone | highest reachability risk |
| vendor service only | broker model; analyze service boundary |

## Symbolic Links And Device Interfaces

A device object may be reachable through:

- DOS symbolic link,
- device interface,
- hard-coded `\Device\Name`,
- setup API enumeration,
- a vendor service acting as a broker.

Common mistake:

```text
no obvious \\.\Name string
  -> assume unreachable
```

Better reasoning:

```text
no DOS link
  -> check device interfaces, service broker, PnP stack, and vendor controller behavior
```

## IOCTL Access Bits

An IOCTL contains access bits:

- `FILE_ANY_ACCESS`,
- `FILE_READ_DATA`,
- `FILE_WRITE_DATA`,
- both read and write.

The I/O manager uses those bits to decide whether a caller's handle access is sufficient for that IOCTL.

Why:

```text
even if a caller opens the device,
an IOCTL with stricter access bits may not be delivered to the driver
```

But access bits are not authorization by themselves.

Risk pattern:

```text
dangerous IOCTL
  + FILE_ANY_ACCESS
  + broad device ACL
  -> high reachability
```

Another risk pattern:

```text
driver exposes harmless-looking open
  -> then uses private subcommand field for privileged operation
  -> no per-operation authorization
```

## `IoValidateDeviceIoControlAccess`

Drivers can call `IoValidateDeviceIoControlAccess` to enforce stricter access checking than the IOCTL access bits alone.

Review questions:

- Does the handler perform extra validation for high-risk commands?
- Is validation done before parsing attacker-controlled fields?
- Is the requested access aligned with the semantic action?
- Are read and write actions separated?
- Are subcommands validated individually?

Why:

```text
IOCTL access bits are coarse;
driver-specific commands often need per-operation checks
```

## Driver-Specific Auth Gates

Some drivers implement custom gates:

- magic value,
- version field,
- process name,
- image path,
- signature check,
- service session state,
- license or hardware presence,
- one-time initialization state.

Research questions:

- Is the check security-critical or just compatibility logic?
- Is it bound to the caller token or only a process name?
- Can a trusted process become a broker?
- Is state cached on a file object?
- Is a handle duplicable across processes?
- Is the gate enforced for every dangerous command?

Why:

```text
custom gates often protect product workflows, not hostile local attackers
```

## Reachability Matrix

Use this matrix in every driver note:

| Layer | Question | Result |
|---|---|---|
| loadability | Can the driver load under current policy? | yes/no/unknown |
| device exposure | Does it expose a named device or interface? | yes/no/unknown |
| open ACL | Who can open it? | system/admin/user/everyone |
| IOCTL access | Which access bits protect dangerous commands? | any/read/write/both |
| custom auth | Does driver perform extra checks? | yes/no/weak/unknown |
| hardware gate | Is real hardware required? | yes/no/partial |
| broker | Is a vendor service required? | yes/no/unknown |

## Why Reachability Decides Exploitability

Example reasoning:

```text
Driver A:
  physical memory R/W
  admin-only device
  blocklisted under current policy

Driver B:
  limited semantic write
  user-openable device
  no per-command authorization
```

Driver A has the stronger primitive. Driver B may be the more reachable attack surface.

This is why serious BYOVD notes separate:

```text
primitive strength
  from
reachability
```

## Defensive Hunting

Inventory:

- device object names,
- symbolic links,
- service names,
- driver paths,
- signer and hash,
- device ACLs,
- controller processes.

High-risk joins:

```text
rare driver load
  + broad device ACL
  + FILE_ANY_ACCESS dangerous IOCTL family
  + non-vendor caller
```

Hardening:

- prefer `IoCreateDeviceSecure` or WDF SDDL assignment for named control devices,
- restrict devices to expected identities,
- avoid `FILE_ANY_ACCESS` for privileged operations,
- validate per-command access,
- block known vulnerable drivers through WDAC and Microsoft recommended driver block rules,
- remove unused hardware utility drivers.

## Review Checklist

```text
driver:
service:
device:
symbolic link/interface:
device creation API:
SDDL/source of security:
FILE_DEVICE_SECURE_OPEN:
open allowed for:
dangerous IOCTL access bits:
per-command validation:
custom auth gate:
broker service:
hardware gate:
blocklist status:
HVCI compatibility:
defensive action:
```

## Study Questions

1. Why is a physical memory primitive not automatically exploitable by a low-privilege user?
2. What is the difference between opening a device and sending a specific IOCTL?
3. Why is `FILE_ANY_ACCESS` dangerous only when combined with a privileged operation and reachable device?
4. How can a vendor service become a security boundary?
5. Why should device ACL findings be documented even if no memory corruption is found?

## References

- Microsoft Learn, `Controlling Device Access`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/controlling-device-access
- Microsoft Learn, `SDDL for Device Objects`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/sddl-for-device-objects
- Microsoft Learn, `IoCreateDevice`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocreatedevice
- Microsoft Learn, `Defining I/O Control Codes`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/defining-i-o-control-codes
- Microsoft Learn, `wdmsec.h` overview:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdmsec/


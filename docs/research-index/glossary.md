# Glossary

Backlinks: [README](../../README.md) | [topic index](topic-index.md) | [learning path](windows-kernel-pwn-learning-path.md)

| Term | Definition |
|---|---|
| IRP | I/O Request Packet; kernel structure used to represent I/O operations sent through drivers. |
| IOCTL | I/O control request used by user mode or kernel mode to send device-specific commands to a driver. |
| `CTL_CODE` | Macro encoding device type, function, transfer method, and access requirement for an IOCTL. |
| `DEVICE_OBJECT` | Kernel object representing a device endpoint created by a driver. |
| `DRIVER_OBJECT` | Kernel object describing a loaded driver, including dispatch routine pointers. |
| SDDL | Security Descriptor Definition Language; text format for object ACLs. |
| `METHOD_NEITHER` | IOCTL method where raw user pointers are passed to the driver; high-risk if not probed and validated. |
| MDL | Memory Descriptor List; describes locked pages for direct I/O. |
| NonPagedPool | Kernel pool memory that cannot be paged out. |
| NonPagedPoolNx | Nonpaged pool that is non-executable by default. |
| PTE/PDE/PDPTE/PML4E | Page-table entries at different x64 translation levels. |
| CR3 | CPU register containing the current paging root physical address. |
| PFN | Page Frame Number, identifying a physical memory page. |
| SMEP | Supervisor Mode Execution Prevention; blocks kernel execution from user pages. |
| SMAP | Supervisor Mode Access Prevention; blocks kernel access to user pages unless explicitly allowed. |
| NX | No-execute permission bit. |
| KASLR | Kernel Address Space Layout Randomization. |
| KCFG | Kernel Control Flow Guard; validates indirect control flow in kernel contexts. |
| XFG | eXtended Flow Guard; stronger call-target validation in supported components. |
| CET | Control-flow Enforcement Technology; includes shadow stack and indirect branch tracking concepts. |
| Shadow Stack | Protected stack copy used to validate returns and resist ROP. |
| VBS | Virtualization-Based Security; uses virtualization isolation for sensitive security services. |
| HVCI | Hypervisor-Enforced Code Integrity, also known as Memory Integrity. |
| KDP | Kernel Data Protection; hypervisor-backed protection for selected kernel data. |
| VT-rp | Intel Virtualization Technology Redirect Protection. |
| HLAT | Hypervisor-managed Linear Address Translation. |
| PatchGuard | Kernel Patch Protection; detects unauthorized modifications to protected kernel structures. |
| KVA Shadow | Kernel Virtual Address Shadow, Windows mitigation related to KPTI/Meltdown. |
| `g_CiOptions` | Code Integrity configuration variable historically discussed in DSE tamper research. |
| DSE | Driver Signature Enforcement. |
| BYOVD | Bring Your Own Vulnerable Driver; abuse of a signed driver exposing dangerous kernel capability. |
| Vulnerable driver blocklist | Microsoft policy list intended to block known vulnerable drivers. |
| ETW | Event Tracing for Windows. |
| Code Integrity | Windows enforcement and telemetry around executable/signature trust. |
| Callback | Kernel routine registered to receive events such as process, thread, registry, or image-load notifications. |
| Minifilter | File-system filter driver model commonly used by security and storage software. |
| LSASS | Local Security Authority Subsystem Service; stores and brokers sensitive authentication state. Study only defensive protections and telemetry; do not dump credentials. |
| PreviousMode | Thread field indicating whether a system call came from user or kernel mode; important for probe/access checks. |
| PPL | Protected Process Light; protection level used for sensitive processes such as LSASS when configured. |
| DACL | Discretionary ACL controlling object access. |
| `IoCreateDeviceSecure` | WDM helper for creating a device object with explicit security. |
| `MmMapIoSpace` | Kernel API for mapping physical device memory; dangerous if exposed to untrusted callers. |
| `RDMSR`/`WRMSR` | Ring 0 instructions for reading/writing model-specific registers. |
| LSTAR | MSR holding the x64 syscall target address. |
| SLAT/EPT | Second-level address translation used by virtualization. |
| WDAC | Windows Defender Application Control, an allowlist-capable code integrity policy system. |

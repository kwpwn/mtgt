# Win32k and GUI Kernel Attack Surface

Backlinks: [README](../../README.md) | [topic index](../research-index/topic-index.md) | [learning path](../research-index/windows-kernel-pwn-learning-path.md)

## Purpose

Explain why Win32k and GUI-related kernel code have historically been important in Windows local privilege escalation research.

## What You Will Learn

- Why GUI functionality moved into kernel mode.
- What the win32k syscall surface represents.
- Why user-mode callbacks created historical bug classes.
- How modern mitigations and detection change win32k exploitation.

## Core Concepts

| Concept | Meaning |
|---|---|
| `win32k.sys`, `win32kfull.sys`, `win32kbase.sys` | Kernel-mode Windows GUI subsystem components. |
| GUI syscalls | System calls exposed for windowing, GDI, and graphics behavior. |
| User-mode callback | Kernel calls back into user mode for hooks/events/copying. |
| Session space | Per-session kernel memory context historically important for GUI objects. |
| Data-only LPE | Privilege escalation by modifying security-relevant data rather than executing new code. |

## Why This Matters

Win32k sits on a complex boundary: user-controlled windows, hooks, messages, and graphical objects interact with kernel data structures. Unit42 notes that user-mode callbacks are historically dangerous because the kernel must release locks or resources before calling into user mode, then revalidate object state afterward.

## Mitigation Notes

| Mitigation | Effect |
|---|---|
| KASLR | Makes object/function address targeting harder. |
| SMEP/NX | Blocks old user-shellcode patterns. |
| KCFG/CET | Constrains indirect call and return reuse. |
| HVCI | Blocks unsigned kernel code end states. |
| Win32k lockdown/component filtering | Reduces syscall surface for sandboxed processes where enabled. |
| EDR anti-LPE logic | May monitor token-style data-only escalation patterns. |

## Detection and Crash Triage

- GUI-heavy local process triggering repeated win32k crashes.
- Bugchecks or user-mode crashes around window creation, destruction, callbacks, or hooks.
- Token or process privilege changes after GUI/syscall anomalies.
- Exploit attempts from sandboxed renderer-like processes.

## Common Misconceptions

- Win32k is not just “graphics”; it is a security boundary.
- User-mode callbacks are not automatically vulnerable; the bug is missing revalidation/lifetime handling.
- Old win32k PoCs are usually version fragile.
- Token stealing examples teach impact, but modern detection often watches these patterns.

## Questions to Ask Yourself

1. Which object crosses the user/kernel GUI boundary?
2. Does a callback allow user mode to change object lifetime?
3. What state must be revalidated after callback return?
4. Which mitigation blocks the original exploitation strategy?
5. What endpoint telemetry would classify this as LPE behavior?

## Related Repo Docs

- [Primitive reasoning framework](primitive-reasoning-framework.md)
- [Kernel pool study map](../windows-heap/kernel-pool-exploitation-study-map.md)
- [Case-study matrix](../research-index/case-study-matrix.md)

## References

- Unit42 Win32k analysis: https://unit42.paloaltonetworks.com/win32k-analysis-part-1/
- SecWiki Windows kernel exploit index: https://github.com/SecWiki/windows-kernel-exploits
- big5-sec Component Filter: https://big5-sec.github.io/posts/component-filter-mitigation/

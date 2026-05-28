# AV Self-Protection Research Index

Updated: 2026-05-27

## Purpose

This index organizes AV/EDR self-protection research by product and by broken
invariant. It is separate from BYOVD because many AV self-protection bypass
writeups do not start with a vulnerable driver primitive. They often start with:

```text
trusted product component
  -> configuration, quarantine, update, service, UI, or IPC path
  -> product self-protection state becomes inconsistent
```

The useful research question is:

```text
which component is trusted to speak for the product, and why?
```

If that component can be confused, spoofed, raced, or made unavailable, the
product may report a protected state while one enforcement layer is weakened.

## Product Case Studies

| Product family | Main document | Primary research angle |
|---|---|---|
| Microsoft Defender | `docs/detection-and-mitigation/av-case-microsoft-defender-self-protection.md` | AM-PPL, ELAM, WdFilter, Tamper Protection, quarantine restore as trusted broker |
| Huorong Internet Security | `docs/detection-and-mitigation/av-case-huorong-self-protection.md` | HIPS daemon/tray/driver split, GUI prompt trust, user-mode to driver IPC trust |
| Qihoo / 360 Total Security | `docs/detection-and-mitigation/av-case-qihoo-360-self-protection.md` | self-protection driver dependency, boot/startup policy, product-driver reachability |
| Cross-product state spoofing | `docs/detection-and-mitigation/av-edr-user-mode-tamper-spoofing.md` | registry state spoofing, version metadata spoofing, update/signature file locking |

## Layer Model

Think about AV self-protection as a stack, not as one feature:

```text
cloud / console / backend health
  -> Windows Security Center / product status reporting
  -> product services and management tools
  -> UI prompt broker and user consent flow
  -> product IPC / RPC / device communication
  -> minifilter and callback drivers
  -> PPL / ELAM / Code Integrity
  -> files, registry, updates, quarantine, signatures
```

A bypass does not need to defeat every layer. It only needs to make one layer
believe a different story from the others.

Examples:

```text
UI says allowed
  != driver actually authenticated the user decision
```

```text
file path is protected from normal writes
  != trusted product broker cannot put content there
```

```text
self-protection process cannot be killed
  != every thread, window, IPC channel, and restart path is protected
```

```text
driver enforces self-protection at runtime
  != driver is guaranteed to load on the next boot
```

## Technique Taxonomy

| Technique family | Broken invariant | Product examples in this repo |
|---|---|---|
| Trusted broker confusion | Product-owned tool or service should not bypass the product's own security boundary | Defender quarantine restore case |
| Quarantine/update path abuse | Restore/update operations should preserve trust context and destination policy | Defender, SNEK Equinox-style update/signature state mismatch |
| UI prompt spoofing | User consent UI should be bound to real user interaction and protected desktop semantics | Huorong prompt cases |
| User-mode to driver IPC spoofing | A driver should authenticate which client is allowed to answer security prompts | Huorong IPC prompt case |
| Process-vs-thread coverage gap | Protecting a process object should also protect thread-level termination routes | Huorong daemon/tray cases |
| Window/message DoS | UI availability should not be a single point of protection failure | Huorong tray crash case |
| Self-protection driver load dependency | Runtime protection should not disappear because a driver is absent at boot | Qihoo/360 historical case |
| Status/version spoofing | Health or version metadata should reflect real sensor and signature state | SNEK Equinox, Defender status surfaces |

## How To Read A Public AV Bypass Writeup

Use this template for each product:

```text
1. Identify the trusted component.
2. Identify what that component is allowed to change.
3. Identify which object or state is supposed to be protected.
4. Ask whether the protected object is accessed directly or through a broker.
5. Ask whether user consent is cryptographically or kernel-authenticated.
6. Ask whether protection covers processes, threads, windows, handles, services,
   drivers, registry, files, and update state consistently.
7. Ask what happens across reboot, service restart, update, and product repair.
```

The "why" is usually not complicated. Security products are large distributed
systems inside one endpoint. A component may be trusted in one context and
dangerous in another.

## Product Comparison

| Question | Defender | Huorong | Qihoo / 360 |
|---|---|---|---|
| Does it rely on Windows PPL/ELAM? | Yes for protected antimalware service model | Not the main public writeup focus | Not the main public writeup focus |
| Does it have kernel drivers? | Yes, including minifilter and platform drivers | Yes, HIPS/protection driver model | Yes, historical self-protection driver model |
| Main public bypass shape studied here | Trusted broker and state/update consistency | UI/IPC/process coverage gaps | driver-start/load dependency |
| Main trust boundary | Product engine/tool vs protected folder/quarantine | user-mode UI/daemon vs kernel driver | boot/service policy vs runtime driver protection |
| Main failure condition | product-owned path can perform action external callers cannot | driver trusts spoofable or fragile user-mode surface | self-protection driver is absent or disabled |
| Research caution | version-specific and heavily patched over time | public PoCs are product-version specific | historical source; verify current versions separately |

## What Not To Mix Together

Do not collapse all of these into "AV bypass."

More precise labels:

- Defender quarantine case: trusted broker / quarantine restore consistency.
- SNEK Equinox: state spoofing and signature/update file lock interference.
- Huorong prompt case: UI consent spoofing and user-mode to driver IPC trust.
- Huorong daemon/tray cases: process-vs-thread and UI availability gaps.
- Qihoo/360 case: self-protection driver load/startup dependency.
- BYOVD AV killer: vulnerable driver gives a kernel primitive or privileged
  termination primitive.

## Research Questions

1. Which component makes the final allow/deny decision?
2. Is that component protected by the OS, by the AV's own driver, or only by
   product convention?
3. Does the product authenticate the caller, or only parse a message?
4. Does the product protect the process but forget thread, window, handle, or
   service paths?
5. Does a trusted repair, restore, quarantine, or update flow bypass normal file
   protections?
6. Is the claimed effect live-only, reboot-persistent, or repaired on update?
7. Does a console view reflect local truth or only cached/reported product state?

## References

- Daniel Santos, "Bypassing Defender's self-protect mechanism":
  https://vovohelo.medium.com/bypassing-defenders-self-protect-mechanism-3b860301fb07
- Microsoft, Protecting anti-malware services:
  https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-
- Microsoft, Tamper Protection:
  https://learn.microsoft.com/en-us/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection
- Microsoft, Defender Antivirus command-line reference:
  https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus
- SweetIceLolly, Huorong vulnerabilities:
  https://github.com/SweetIceLolly/Huorong_Vulnerabilities
- Huorong official product page:
  https://www.huorong.cn/document/info/productions/106
- The Antivirus Hacker's Handbook, O'Reilly landing page:
  https://www.oreilly.com/library/view/the-antivirus-hackers/9781119028758/
- 360 Total Security official feature page:
  https://www.360totalsecurity.com/en/features/360-total-security/

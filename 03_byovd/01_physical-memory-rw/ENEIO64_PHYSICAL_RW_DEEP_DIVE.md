# eneio64.sys / CVE-2020-12446 Physical R/W Deep Dive

Sources:

- xacone write-up: https://xacone.github.io/eneio-driver.html
- Mirror/reference: https://www.hendryadrian.com/eneio-driver/
- LOLDrivers database: https://www.loldrivers.io/

`eneio64.sys` is associated with RGB/hardware-control software. The key issue is that it exposes low-level hardware capabilities that can be used as a BYOVD primitive.

Primitive class:

```text
physical memory read/write
MSR access
I/O port access
```

The 2025-era write-up is useful because it discusses exploitation under modern Windows/HVCI assumptions, not just a legacy CVE note.

## 1. Why an Old CVE Still Matters

CVE-2020-12446 is not new. It still matters because:

- old signed drivers remain loadable on many systems,
- hardware/RGB utilities are widely distributed,
- blocklists lag or depend on policy state,
- the primitive remains strong if the driver loads,
- modern exploit research can repurpose old driver bugs against new Windows versions.

BYOVD risk is about signed vulnerable code availability, not CVE freshness alone.

## 2. Primitive Set

`eneio64.sys` is interesting because it exposes several low-level capability classes:

| Capability | Exploit value |
|---|---|
| Physical memory R/W | Kernel object/data manipulation |
| MSR access | KASLR leak or syscall-control research |
| Port I/O | Hardware/platform-specific abuse |

For Windows LPE, physical R/W is the most generally useful primitive.

MSR access is powerful but crash-prone.

Port I/O is more platform-specific and less directly useful for generic LPE.

## 3. Why Physical R/W Is the Core Exploit Path

Physical R/W can be converted into:

- arbitrary kernel virtual read/write,
- token DKOM,
- process protection modification,
- page-table manipulation in weaker environments,
- selected kernel global modifications.

The usual route:

```text
driver physical R/W
  -> find/derive CR3
  -> page-table walk
  -> translate kernel VA to PA
  -> read/write target object
```

This is conceptually close to ASTRA direct DKOM.

## 4. Why Virtual-to-Physical Translation Is the Main Lesson

The xacone write-up emphasizes page-table walking because that is the hard part after getting physical access.

The driver operates on physical memory. Windows objects are referenced virtually.

Translation lets the exploit move from:

```text
I can read physical address X
```

to:

```text
I can read/write ntoskrnl and EPROCESS fields by virtual address
```

This is the key mental bridge.

## 5. Why This Is Better Than Blind Scanning

Blind scan:

- locate objects by signatures,
- hope offsets/signatures are unique,
- write based on guessed location.

Page-table translation:

- locate object by normal kernel pointers,
- translate exactly,
- write exact field.

For physical-memory BYOVD, page-table translation is the more reliable strategy when you can obtain or infer CR3.

## 6. HVCI Compatibility Does Not Mean Safety

The write-up notes modern/HVCI relevance. The important distinction:

- HVCI validates code integrity and driver compatibility.
- It does not prove the driver's IOCTL semantics are safe.
- If a signed/HVCI-compatible driver exposes physical memory, it remains dangerous.

This is why driver blocklists and WDAC are critical.

## 7. Why RGB/Hardware Drivers Are a BYOVD Hotspot

These drivers often need low-level access:

- MSR,
- port I/O,
- PCI config,
- physical memory,
- MMIO mappings,
- sensor/control registers.

Developers sometimes expose those primitives too broadly to user mode.

The result:

```text
RGB utility feature -> kernel exploit primitive
```

Security teams should treat old hardware-control drivers as high-risk even if the user-mode app looks harmless.

## 8. MSR Access: Useful but Usually Secondary

MSR read can leak:

- syscall entry,
- CPU state,
- kernel pointers depending on MSR.

MSR write can redirect:

- syscall path,
- CPU behavior,
- machine-wide state.

Why it is usually secondary:

- high crash risk,
- multi-core complications,
- unnecessary for data-only LPE,
- more likely to trip integrity/detection.

Use MSR read for anchors. Avoid MSR write unless the research question specifically needs it.

## 9. I/O Port Access

Port I/O is less generic than physical R/W.

It can matter for:

- chipset/platform control,
- embedded controllers,
- legacy hardware registers,
- specific security-sensitive hardware paths.

But for general Windows LPE:

- it is not the simplest path,
- it is machine-specific,
- it can crash hardware/platform state.

Physical memory R/W remains the cleaner primitive.

## 10. Direct DKOM Applicability

If the exploit can translate:

```text
current_eprocess.Token VA -> physical address
```

then direct token DKOM applies just like ASTRA:

```text
save original token
write System token fast-ref
spawn child
restore original token
```

This is attractive because it avoids:

- shellcode,
- page-table modification,
- MSR write,
- control-flow hijack.

## 11. Stability Across Versions

Stable:

- x64 page-table mechanics,
- physical R/W concept,
- data-only token swap concept.

Variable:

- driver load policy,
- vulnerable driver version,
- blocklist state,
- `_EPROCESS` offsets,
- CR3 discovery method,
- VBS/KDP-protected regions.

This makes eneio64 useful for research, but not automatically portable without offset/translation validation.

## 12. BSOD Risk Matrix

| Operation | Risk | Why |
|---|---|---|
| Driver load | Low-medium | Old driver may be blocked or incompatible. |
| Physical read | Low-medium | Bad mappings can fail. |
| Physical write | High | Wrong PA corrupts kernel/hardware state. |
| Page-table walk | Low | Read-only if implemented safely. |
| Token DKOM | Medium | Small write but offset-sensitive. |
| MSR read | Low | Read-only. |
| MSR write | High | Global CPU path manipulation. |
| Port I/O | Medium-high | Platform-specific side effects. |

## 13. Defensive View

Hunt for:

- `eneio64.sys`, `ene.sys`,
- RGB/hardware-control drivers on enterprise endpoints,
- driver load from user-writable path,
- device open by non-vendor process,
- suspicious SYSTEM child process after driver load,
- CodeIntegrity events,
- known LOLDrivers hash matches.

Controls:

- WDAC deny old known-bad hashes,
- remove unused RGB utilities,
- keep vulnerable driver blocklist enabled,
- inventory hardware utility drivers.

## 14. Final Takeaway

`eneio64.sys` is a strong example of why old hardware utility drivers remain relevant. The exploit value is not the age of the CVE. The value is:

```text
signed driver + physical R/W + modern systems still allow it to load
```

The safest exploit engineering path is again data-only:

```text
physical R/W -> VA/PA bridge -> minimal kernel object write
```


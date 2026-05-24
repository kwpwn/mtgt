# MSI RTCore64.sys / CVE-2019-16098 Deep Dive

Sources:

- CVE summary: https://securityvulnerability.io/vulnerability/CVE-2019-16098
- eSecurityPlanet BlackByte reporting: https://www.esecurityplanet.com/threats/ransomware-group-bypasses-edr-products/
- HITCON 2022 slides mention RTCore64 IOCTL behavior: https://hitcon.org/2022/slides/Hack-The-Real-Box-an-analysis-of-multiple-campaigns-by-APT41s-subgroup-Earth-Longzhi.pdf
- Cyberbit RTCore article: https://www.cyberbit.com/campaign/msi-afterburner-rtcore-driver-exploitation/

`RTCore64.sys` is the MSI Afterburner / RivaTuner class BYOVD. It is older but still important because it is widely known in real-world attacks.

Primitive class:

```text
arbitrary kernel virtual memory read/write
I/O port access
MSR access in some descriptions
```

## 1. Why RTCore64 Is Operationally Important

It is bundled with popular GPU tuning software.

That means:

- defenders may see it as legitimate,
- attackers can bring a known signed copy,
- gamers/admin workstations may already have it,
- ransomware has used it to bypass EDR.

It is a canonical BYOVD driver.

## 2. Virtual Kernel R/W vs Physical R/W

RTCore-style arbitrary memory access is often described as direct kernel memory read/write through IOCTLs.

This differs from ASTRA:

ASTRA:

```text
physical address -> map page -> user writes
```

RTCore:

```text
kernel virtual address -> driver performs read/write
```

If the primitive truly accepts kernel virtual addresses, exploitation is simpler:

- no CR3 discovery,
- no page-table walk,
- no physical scanning,
- direct write to `_EPROCESS.Token` once address is known.

But you still need:

- kernel base leak,
- object address discovery,
- offsets,
- validation.

## 3. Why Virtual R/W Is Easier Than Physical R/W

Virtual R/W aligns with how Windows objects are referenced.

Targets:

- `_EPROCESS`,
- `_TOKEN`,
- kernel globals,
- driver objects,
- callback arrays.

All are normally discussed by virtual address.

If a driver provides virtual R/W:

```text
write(kernel_va, bytes)
```

you skip the whole VA->PA bridge.

This makes the exploit shorter and less architecture-heavy.

## 4. Why It Is Still Dangerous Under HVCI

Virtual R/W through a signed driver can still modify normal VTL0 kernel data.

HVCI helps with:

- code integrity,
- unsigned driver blocking,
- executable memory restrictions.

It does not automatically stop:

- signed vulnerable driver performing writes,
- data-only token mutation,
- process protection field mutation.

Again, WDAC/blocklist is the practical control.

## 5. Why Ransomware Uses RTCore64

Ransomware does not necessarily need a polished SYSTEM shell. It needs:

- disable EDR,
- kill security processes,
- tamper with callbacks,
- gain kernel-level capability,
- bypass user-mode self-defense.

RTCore64 gives a broad primitive. Operators can use it to disable defenses before ransomware payload execution.

The BlackByte reporting is an example of BYOVD as defense evasion rather than academic LPE.

## 6. Natural Exploit Routes

With virtual kernel R/W, common routes are:

### Token swap

```text
find System EPROCESS
find current EPROCESS
copy token fast-ref
```

Pros:

- simple,
- data-only,
- one pointer write.

Cons:

- offset-sensitive,
- detection possible,
- reference semantics dirty.

### PPL/protection tamper

Modify process protection fields.

Pros:

- useful for LSASS/EDR access.

Cons:

- very version-sensitive,
- likely monitored,
- narrower impact than full token.

### Callback tamper

Modify kernel callback state.

Pros:

- defense evasion.

Cons:

- PatchGuard/EDR-sensitive,
- high delayed crash risk.

## 7. Why Virtual R/W Can Be More Dangerous Than Physical R/W Operationally

Physical R/W is lower-level and theoretically more powerful.

But virtual R/W is often easier operationally:

- simpler exploit code,
- fewer translation failures,
- easier target selection,
- faster development,
- fewer architecture assumptions.

So:

```text
physical R/W may be stronger as a primitive,
virtual R/W may be more convenient as an exploit interface
```

## 8. BSOD Risk Matrix

| Stage | Risk | Reason |
|---|---|---|
| Driver load | Low-medium | Blocklist/incompatibility. |
| Kernel virtual read | Medium | Bad VA can fault inside driver. |
| Kernel virtual write | High | Wrong VA corrupts kernel memory. |
| Token swap | Medium | Offset-sensitive. |
| Callback tamper | High | PatchGuard/delayed bugcheck. |
| MSR write | High | If available/used. |

Virtual R/W removes VA->PA risk but not wrong-target risk.

## 9. Stability Across Versions

Stable:

- driver protocol for vulnerable version,
- token-swap concept,
- kernel virtual addressing model.

Variable:

- vulnerable driver version,
- blocklist/WDAC,
- `_EPROCESS` offsets,
- kernel object layout,
- KASLR leak method,
- target security product behavior.

## 10. Defensive View

Hunt for:

- `RTCore64.sys`, `RTCore32.sys`,
- MSI Afterburner/RivaTuner/EVGA Precision old versions,
- driver load on servers/non-gaming endpoints,
- suspicious service creation,
- security process tamper after driver load,
- Defender/anti-cheat alerts blocking RTCore.

Controls:

- update MSI Afterburner,
- remove unneeded tuning tools,
- WDAC deny old vulnerable versions,
- enforce driver blocklist.

## 11. Final Takeaway

RTCore64 is important because it represents the most operator-friendly BYOVD primitive:

```text
signed driver + virtual kernel R/W
```

It may be less "low-level interesting" than physical R/W, but it is easier to weaponize. That is why it appears repeatedly in real-world BYOVD discussions.


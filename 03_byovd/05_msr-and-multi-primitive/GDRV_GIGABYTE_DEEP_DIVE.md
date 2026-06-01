# Gigabyte gdrv.sys Deep Dive

Sources:

- Amit Moshel write-up: https://amitmoshel1.github.io/posts/exploiting-gdrv-sys-a-vulnerable-gigabyte-driver/
- CVE-2019-7630 summary: https://vuldb.com/vuln/152268
- CrowdStrike BYOVD intrusion discussion mentioning Gigabyte driver: https://www.crowdstrike.com/en-us/blog/falcon-prevents-vulnerable-driver-attacks-real-world-intrusion/

`gdrv.sys` is a Gigabyte APP Center driver. Public research describes multiple dangerous capabilities, including memory mapping/arbitrary write and MSR write.

Primitive classes:

```text
physical/memory mapping path
arbitrary write primitive
MSR write primitive
```

## 1. Why gdrv.sys Is a Good Study Case

It shows a common driver pattern:

- hardware utility driver,
- multiple IOCTLs,
- several dangerous primitives,
- some primitives are easier to exploit than others.

The public write-up notes two routes:

- memory mapping/token overwrite idea,
- arbitrary write primitive used directly after mapping route problems.

This is realistic exploit engineering: choose the primitive that works reliably, not the one that looks best on paper.

## 2. MSR Write Primitive

The CVE-2019-7630 summary describes an IOCTL exposing `wrmsr` without proper MSR filtering.

Why this matters:

- arbitrary MSR write can redirect syscall entry,
- invalid writes cause denial of service,
- control-flow impact may be possible.

Why it is usually not the best LPE route:

- high crash risk,
- global CPU state,
- multi-core issues,
- mitigation interactions.

MSR write is powerful but uncomfortable.

## 3. Arbitrary Write Primitive

An arbitrary write primitive is often more useful than MSR write for LPE.

If it can write controlled data to controlled kernel VA:

- token swap,
- protection field tamper,
- function pointer tamper,
- data-only policy change.

If it is constrained:

- size,
- alignment,
- source buffer,
- write-what vs write-where,
- pointer validation,

then target selection matters.

The public write-up moved toward arbitrary write because the memory mapping route had practical issues.

## 4. Why "Best Primitive" Means "Most Reliable"

Primitive ranking is context-dependent:

| Primitive | Looks strong | Practical problem |
|---|---|---|
| MSR write | Can hijack syscall | Very crash-prone |
| Physical map | Broad memory access | Need translation/scanning |
| Arbitrary kernel write | Direct data tamper | Need target address/offset |

For token LPE, arbitrary write can be the best because:

- only one pointer-sized write needed,
- no page table walk if kernel VA known,
- no control-flow hijack,
- no MSR restore.

## 5. Token Swap Route

The natural route:

```text
leak/find EPROCESS
read System token
write System token into current process token field
```

If only arbitrary write exists but no read:

- need separate leak,
- use known exported/global pointers,
- use driver read primitive if available,
- or choose a write target that does not require reading original value.

If arbitrary read/write exists:

- token swap is straightforward.

## 6. Memory Mapping Route Challenges

Memory mapping vulnerabilities can fail in practice because:

- mapping range restrictions,
- cache attributes,
- invalid physical address handling,
- driver protocol complexity,
- lack of VA->PA bridge,
- HVCI/VBS behavior.

This explains why a write-up may abandon one primitive and use another. Exploit development is reliability-driven.

## 7. BSOD Risk Matrix

| Primitive | Risk | Why |
|---|---|---|
| MSR write | High | Global CPU behavior. |
| Physical map/write | High | Wrong PA corrupts memory. |
| Arbitrary write | Medium-high | Wrong VA corrupts kernel object. |
| Token swap | Medium | Small write but offset-sensitive. |
| Callback/table patch | High | PatchGuard/delayed crash. |

## 8. Stability Across Versions

Stable:

- driver protocol for exact vulnerable version,
- arbitrary write concept,
- token swap concept.

Variable:

- Windows offsets,
- kernel base leak method,
- target object discovery,
- driver blocklist,
- Gigabyte driver versions,
- IOCTL behavior.

## 9. Defensive View

Hunt for:

- `gdrv.sys`,
- Gigabyte APP Center old drivers,
- MSR write capable driver loads,
- suspicious kernel driver service creation,
- token/PPL/security process anomalies after load.

Controls:

- update/remove Gigabyte APP Center,
- WDAC deny known vulnerable hashes,
- enable vulnerable driver blocklist,
- monitor hardware utility driver loads.

## 10. Final Takeaway

`gdrv.sys` teaches that exploit choice is pragmatic. If a driver exposes MSR write, physical mapping and arbitrary write, the most reliable LPE path may be the least flashy one:

```text
arbitrary data write -> token field
```

Strong primitives are only useful if they can be stabilized.


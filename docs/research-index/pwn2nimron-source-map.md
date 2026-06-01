# Pwn2Nimron Source Map

Updated: 2026-05-28

## Purpose

This document tracks public research material associated with `pwn2nimron.com` and Ori Nimron that is relevant to this repository's Windows research themes.

The point is not to mirror exploit code. The point is to classify public material by:

- primitive shape,
- broken invariant,
- bridge to impact,
- and which local notes should be read next.

## Source status note

At review time, direct browsing of the site did not behave like a normal article index. The root blog page resolved to a public writeup titled:

- `CVE-2026-40369 // Arbitrary Kernel Address Increment`

Treat this file as a public-source map for currently visible material, not as proof that every historical post on the site has been cataloged.

Primary public source:

- [pwn2nimron.com/blog](https://pwn2nimron.com/blog)

Related public identity links visible from the page:

- [Ori Nimron on GitHub](https://github.com/orinimron123)
- [Ori Nimron on X](https://x.com/orinimron123)

## Current mapped item

### CVE-2026-40369 - Arbitrary Kernel Address Increment via NtQuerySystemInformation

Source:

- [pwn2nimron.com/blog](https://pwn2nimron.com/blog)

High-level classification:

```text
restricted user-mode origin
  -> reachable NT syscall surface
  -> limited kernel arithmetic write primitive
  -> exploit chain needs information and object-layout bridges
```

Why it matters:

- it is a good example of why small primitives still matter,
- it emphasizes sandbox-constrained attack surface rather than classic wide-open admin context,
- it explicitly pairs a weak primitive with an information bridge,
- it reinforces the idea that exploit chains are often composition problems.

What to learn from it:

1. Weak primitive reasoning:
   an increment primitive is not "almost useless"; it is a state-tamper building block.
2. Constraint-driven attack surface:
   Win32k lockdown and restricted tokens reshape which syscalls remain relevant.
3. Information bridge discipline:
   side-channel KASLR recovery can be enough to make a weak primitive useful.
4. Cleanup and state restoration thinking:
   public exploit writeups often contain reliability and state-repair logic that reveal what invariants were disturbed.

Local reading path:

- `docs/kernel-research/prefetch-kaslr-side-channel-notes.md`
- `docs/kernel-research/kernel-base-from-lstar-pattern-scan.md`
- `docs/kernel-research/offensive-driver-exploitability-map.md`
- `docs/kernel-research/kernel-object-layout-drift.md`
- `docs/windows-internals/object-manager-and-handle-tables.md`

## Why this source is useful for this repo

This blog is worth tracking because it tends to sit in the overlap between:

- modern Windows exploit development,
- sandbox-constrained reasoning,
- weak primitive upgrade logic,
- and practical chain composition.

That makes it more educational than sources that jump straight to "got SYSTEM" without explaining the bridges.

## How to use future posts from this source

When a new post appears, classify it using this template:

1. Initial origin:
   renderer, low-IL, standard user, admin, service, or kernel-adjacent.
2. Primitive:
   read, write, increment, decrement, type confusion, stale handle, logic bug, side channel.
3. Information bridge:
   KASLR, object discovery, layout recovery, token or handle discovery.
4. Impact bridge:
   token, callback state, object pointer, broker confusion, persistence, telemetry tamper.
5. Failure modes:
   build drift, mitigation pressure, CPU dependence, sandbox variance.

If a future post fits one of those shapes, it belongs in this repo.


# Prefetch KASLR Side-Channel Notes

Updated: 2026-05-28

## Purpose

This note explains why a user-mode prefetch timing oracle can matter to Windows kernel research.

The goal is not to turn this into a copy-paste exploit recipe. The goal is to understand a recurring bridge:

```text
no kernel read primitive yet
  -> still recover useful kernel placement information
  -> reduce uncertainty for later primitive upgrade or bug validation
```

That bridge matters because many modern exploit chains do not begin with full arbitrary read.

## Primary public sources

- `exploits-forsale/prefetch-tool`:
  [https://github.com/exploits-forsale/prefetch-tool](https://github.com/exploits-forsale/prefetch-tool)
- Exploits For Sale writeup for a Windows 11 24H2 exploit chain:
  [https://exploits.forsale/24h2-nt-exploit/](https://exploits.forsale/24h2-nt-exploit/)
- EntryBleed background for Linux-style inspiration:
  [https://www.willsroot.io/2022/12/entrybleed.html](https://www.willsroot.io/2022/12/entrybleed.html)
- Related public writeup by Ori Nimron:
  [https://pwn2nimron.com/blog](https://pwn2nimron.com/blog)

## What this technique is really about

This is a side-channel question, not a direct memory-disclosure question.

The attacker is not reading kernel bytes directly.

Instead, the attacker tries to infer:

- whether a guessed kernel virtual address range is mapped,
- whether cache behavior differs for mapped versus unmapped guesses,
- whether those timing differences are stable enough to reveal the rough location of `ntoskrnl`.

That means the information gained is weaker than a read primitive, but often strong enough to matter.

## Why KASLR matters in practice

Kernel ASLR does not make every bug disappear. But it raises the cost of using many primitives.

If you have:

- a write-only primitive,
- a small increment/decrement primitive,
- a type-confusion path with no disclosure,
- a limited user-mode to kernel state confusion,

then knowing where the kernel image sits can remove a major source of uncertainty.

So the research question becomes:

```text
Can I recover enough kernel placement information
without already having a kernel memory disclosure?
```

That is exactly where this class of side channel becomes interesting.

## The basic intuition

The public `prefetch-tool` code scans a broad canonical kernel-address range and times prefetch-related behavior for candidate addresses.

Very high-level idea:

```text
guess address
  -> trigger some state transition / syscall path
  -> issue prefetch instructions on guessed address
  -> measure timing
  -> compare many guesses
  -> detect abnormal region
```

The hypothesis is:

- mapped kernel ranges perturb the microarchitectural state differently,
- those differences leak into timing,
- repeated sampling can separate signal from noise.

This is why the tool is fundamentally statistical.

## Why the code scans a range instead of "finding the exact base"

Because side-channel signals are noisy and coarse.

In the public PoC:

- the scan range is a high canonical kernel range,
- the step size is coarse,
- the output is treated as a region candidate rather than a byte-accurate truth source.

That is the right mindset.

Side channels rarely begin as exact symbolic answers. They begin as confidence gradients.

## Why the public tool uses 1 MB stepping

The public code uses:

```text
STEP = 0x100000
```

Why would someone do that?

Because the first goal is not exact PE parsing. The first goal is to locate the image neighborhood.

Tradeoff:

- smaller step size gives more resolution,
- but costs more time and may amplify noise,
- larger step size gives faster broad localization,
- but may miss fine-grained boundaries.

For a KASLR bypass side channel, coarse localization can already be enough to bootstrap later reasoning.

## Why repeated sampling matters

The public code repeatedly measures each candidate address and then:

- averages timings,
- or uses simple frequency-based heuristics,
- or requires repeated matching leaks before trusting the result.

Why?

Because the signal is unstable.

Real systems add noise from:

- scheduler movement,
- frequency scaling,
- background activity,
- cache warmth,
- CPU family differences,
- firmware and microcode behavior,
- virtualization effects.

A single timing sample is not a finding. It is just a hint.

## Why the Intel and AMD paths differ

The public repository includes separate heuristics for:

- Intel,
- Intel N200,
- AMD,
- AMD mobile.

That is one of the most important lessons in the repo.

The lesson is not "copy these thresholds."

The real lesson is:

```text
microarchitectural side channels are platform-shaped
```

Why this matters:

- one CPU family may show lower timings for the interesting region,
- another may show higher timings,
- one system may need mode/median logic,
- another may need average/deviation logic,
- one may be reliable,
- another may be flaky.

If a researcher ignores CPU dependence, they will overgeneralize a local success into a false universal claim.

## Why the code performs a bad syscall before timing

The public assembly includes a deliberately invalid syscall path before timing probes.

Why might that help?

At a high level, it appears intended to perturb execution state in a repeatable way so that subsequent timing on guessed addresses becomes more distinguishable.

The key research lesson is not the exact instruction sequence. It is the pattern:

```text
prepare state
  -> measure probe
  -> repeat enough times
  -> classify region by relative timing
```

Side channels often need a "setup" phase before the measurement is meaningful.

## Why prefetch instructions are attractive for research

Because they can sometimes interact with address translation and cache hierarchy in ways that leak information without requiring a normal architecturally visible read.

That does not mean every prefetch becomes a disclosure oracle.

It means the following question is worth studying:

```text
Does the CPU treat prefetched mapped kernel addresses differently enough from unmapped guesses
that user mode can measure the difference?
```

That is the actual primitive hypothesis.

## Why this does not automatically break everything

This is not a universal bypass in the strong sense.

Its value depends on:

- CPU family,
- Windows build,
- scheduler noise,
- timing environment,
- how much precision the later exploit stages need,
- whether the exploit already has some partial anchor.

A weak but stable region leak can still be enough.

A noisy leak that only works on one class of Intel laptop is much less generally useful.

Research notes should preserve that distinction.

## Relationship to kernel-base discovery from syscall anchors

This repo already has:

- `docs/kernel-research/kernel-base-from-lstar-pattern-scan.md`

That note explains a different strategy:

- start from a trusted kernel-entry anchor such as syscall machinery,
- then search memory patterns or headers to recover the image base.

The prefetch side-channel note sits earlier in the chain.

Comparison:

| Technique | What it assumes | What it gives |
|---|---|---|
| LSTAR/syscall-anchor reasoning | some anchor or primitive already reveals a kernel-adjacent address | more direct base recovery path |
| Prefetch timing side channel | no direct kernel disclosure, only user-mode timing measurement | probabilistic image-region localization |

This is why the prefetch technique is interesting: it can act before a conventional address disclosure exists.

## Relationship to sandbox escapes

Public writeups around this topic emphasize sandbox settings where:

- the initial process is heavily restricted,
- the Win32k surface may be unavailable,
- syscall availability is narrower,
- and a side channel can still help turn a weak primitive into a workable chain.

That is a strong research lesson.

Modern exploitation is often:

- not "one bug, total victory",
- but "one weak primitive, then several information and state bridges."

This technique belongs in that second category.

## Failure modes

### 1. Signal does not separate from noise

You collect timings, but the candidate region does not stand out.

Why:

- CPU family mismatch,
- frequency scaling,
- VM behavior,
- low sample count,
- heuristic thresholds not suited for that machine.

### 2. Region is found, but precision is insufficient

The leak may narrow the image neighborhood but not produce the exact base needed for later steps.

Why:

- coarse scan step,
- broad timing plateau,
- image-layout assumptions too optimistic.

### 3. Result is locally true, globally false

A heuristic that works on one test laptop may fail on desktops, servers, VMs, or newer microcode.

This is a classic side-channel research trap.

### 4. Later exploit stage needs stronger disclosure

If the later chain requires:

- exact structure addresses,
- exact object pointers,
- reliable pointer chasing,

then a rough KASLR bypass alone may not be enough.

## Why this belongs in a Windows research resource

Because it trains the right mindset:

- not every useful primitive is a read/write primitive,
- microarchitectural behavior can act as an oracle,
- kernel exploitation often depends on information quality, not only corruption power,
- CPU-dependent reliability must be documented explicitly.

This also pushes the reader to ask better questions:

```text
What is the weakest information signal that is still enough
to make my later primitive usable?
```

That is a much stronger exploit-development question than "do I have arbitrary read yet?"

## Reading path in this repo

1. `docs/kernel-research/prefetch-kaslr-side-channel-notes.md`
2. `docs/kernel-research/kernel-base-from-lstar-pattern-scan.md`
3. `docs/kernel-research/runtime-pdb-symbol-resolution.md`
4. `docs/kernel-research/kernel-object-layout-drift.md`
5. `docs/kernel-research/offensive-driver-exploitability-map.md`

## Study questions

1. Why can a probabilistic kernel-region leak still be valuable without exact pointer disclosure?
2. Why is CPU-family-specific heuristic logic a sign of a real side-channel problem rather than a polished universal primitive?
3. Why does a side-channel-assisted KASLR bypass help limited write primitives more than full arbitrary read primitives?
4. Why should timing-based research notes always record test hardware and scheduler assumptions?
5. Why is "works on Intel, flaky on AMD" a research result, not just an implementation flaw?


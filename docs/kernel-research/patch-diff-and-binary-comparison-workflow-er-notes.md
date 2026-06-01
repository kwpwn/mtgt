# Patch Diff And Binary Comparison Workflow From ER Article 02

Updated: 2026-05-28

## Purpose

This note distills the research workflow from Alexandre Borges's
`Exploiting Reversing (ER) series: Article 02 - Windows kernel drivers part 02`.

Source PDF:

- `E:\Dowloads\exploit_reversing_02-2.pdf`

The article uses Windows SMB patch analysis as a teaching case. The important
result is not the specific SMB target. The important result is the workflow:

```text
CVE / patch bulletin
  -> identify patched binaries
  -> extract old/new versions
  -> compare functions and changed regions
  -> build exploitability hypotheses
  -> validate against code and invariants
```

Use it with:

- `docs/kernel-research/ida-ghidra-driver-re-patterns.md`
- `docs/kernel-research/public-poc-reading-and-annotation-template.md`
- `docs/kernel-research/win32k-case-study-atlas.md`
- `docs/debugging/windbg-kernel-research-workflow.md`
- `docs/research-index/technique-writing-standard.md`

## Why Patch Diffing Deserves Its Own Note

Many people say "do a bindiff" as if the diff is the conclusion. It is not.

A patch diff only gives:

```text
what changed
```

Research needs:

```text
why it changed
what invariant the old code violated
what attacker-controlled path can reach it
what preconditions still remain
what mitigations affect the old behavior
```

The article is useful because it walks through the work needed before the diff
actually becomes vulnerability understanding.

## The Core Workflow

The reusable workflow is:

```text
1. Start from a CVE or patch bulletin.
2. Identify the product role and affected subsystem.
3. Determine which binaries changed.
4. Extract pre-patch and post-patch versions.
5. Normalize the analysis environment.
6. Compare functions, basic blocks, and imports.
7. Classify meaningful changes versus noise.
8. Form hypotheses about the broken invariant.
9. Trace the reachable code path.
10. Decide whether the issue looks memory-corruption, logic, state, or policy related.
```

If you skip steps 2 and 3, you often diff the wrong thing.

## Step 1: Start With Product Context, Not Only CVE Metadata

The article uses SMB as a case study. That matters because a subsystem name gives
you a model of likely code families before the diff starts.

Examples of questions:

- Is it client-side, server-side, or both?
- Is the affected code in kernel, service, minifilter, RPC, Win32k, or user-mode
  helper?
- Is the path parser-heavy, state-machine-heavy, memory-copy-heavy, or access
  control-heavy?

Why this matters:

```text
the same diff pattern means different things in a parser, a state machine, and an
object-lifetime path
```

## Step 2: Identify Which Binary Actually Changed

Patch analysis often fails because people diff the first binary name they
recognize instead of the binary that implements the vulnerable behavior.

The article's SMB walk-through is a good reminder that one feature can span:

- client binaries,
- server binaries,
- helper DLLs,
- transport components,
- filesystem or network stack pieces.

Research rule:

```text
subsystem name
  !=
single binary
```

Good first-pass questions:

- Which files did the patch update?
- Which of those files implement the described behavior?
- Which changed files are likely data/schema/support noise rather than the
  vulnerable path?

## Step 3: Patch Extraction Is Part Of The Method

The article shows extraction from Microsoft update packages. The exact commands are
not the durable lesson. The durable lesson is artifact discipline:

- preserve old and new binaries clearly,
- keep version metadata,
- keep architecture and build aligned,
- avoid mixing files from different revisions,
- record where each binary came from.

Why:

```text
bad artifact hygiene produces fake diffs
```

If you compare:

- different architectures,
- GDR/LDR style mismatches,
- different cumulative-update baselines,
- binaries with unrelated compiler churn,

then the diff gets noisier than the vulnerability itself.

## Step 4: Choose The Right Comparison Tool For The Question

The article uses Diaphora. That is reasonable because it gives:

- matched functions,
- unmatched functions,
- partially matched functions,
- quick visual prioritization.

But tool choice should follow the question:

| Question | Useful tool shape |
|---|---|
| Function identity and similarity | Diaphora / BinDiff-style matching |
| Exact instruction-level changes | Disassembler diff or manual listing comparison |
| Strings/imports/config changes | PE/metadata diff |
| Runtime behavior around a suspect path | Debugger / tracing / repro harness |

The point is not tool loyalty. The point is:

```text
use the diff to narrow scope, then switch to semantic analysis
```

## Step 5: Treat Similarity Scores As Triage, Not Truth

One of the easiest mistakes in patch diffing is over-trusting similarity
percentages.

High similarity can still hide:

- a single decisive bounds check,
- a refcount fix,
- a new state validation,
- a previously missing null/object test,
- a reorder that changes lifetime safety.

Low similarity can still be noise caused by:

- compiler reshaping,
- inlining,
- split/merged helper functions,
- logging or telemetry additions,
- unrelated refactors in the same binary.

So the right question is not:

```text
which function changed the most?
```

It is:

```text
which change best explains the vulnerability description and the subsystem model?
```

## Step 6: Build Invariant Hypotheses

The article's biggest transferable lesson is that patch analysis should produce
invariants.

Examples of invariant categories:

- length or bounds invariant,
- state-machine invariant,
- object lifetime invariant,
- permission or policy invariant,
- initialization invariant,
- cross-component consistency invariant.

A good patch-diff note should say something like:

```text
before patch, code trusted X before validating Y
after patch, validation of Y occurs before X is consumed
therefore the broken invariant was ...
```

That is much stronger than "function changed around this line."

## Step 7: Reachability Still Matters

A changed function is not automatically reachable from an attacker-controlled path.

After identifying a likely fix site, ask:

- What input reaches it?
- Through which protocol, IOCTL, syscall, callback, or parser stage?
- Is authentication required?
- Is the path pre-auth, post-auth, local-only, or admin-only?
- Does the changed code run once, repeatedly, or only during teardown?

Why this matters:

```text
diff significance
  !=
practical exploitability
```

The article is framed as vulnerability research, so the next layer after binary
comparison is always code-path ownership.

## Step 8: Compare Old And New Logic, Not Only Old And New Bytes

For the narrowed candidate functions, compare semantically:

- checks added,
- order changed,
- helper split out,
- error path strengthened,
- copy length changed,
- object acquisition or release moved,
- lock or reference added,
- state flag set earlier,
- structure field initialized before use.

Useful translation:

```text
patch adds condition
  -> old code accepted a bad state

patch moves release
  -> old code had lifetime/race pressure

patch changes size math
  -> old code may have overflow/underflow or truncation risk
```

## Step 9: Keep Noise Separate From Candidate Security Changes

The article's comparison screenshots are useful because they show not everything in
a patch is equally interesting.

Classify changes into:

- likely security-relevant,
- likely compiler or layout churn,
- likely telemetry or logging,
- likely adjacent cleanup,
- unclear.

That keeps the research note honest. Otherwise, every diff starts looking like a
critical bug when it may only be build churn.

## Why SMB Is A Good Teaching Case

SMB is a useful teaching target because it forces the researcher to practice:

- subsystem decomposition,
- multi-binary scoping,
- patch package extraction,
- protocol-path thinking,
- prioritization among many changed routines.

Even if your real target is not SMB, the method transfers cleanly to:

- Win32k updates,
- minifilter changes,
- filesystem drivers,
- network stack components,
- OEM utility drivers,
- hypervisor and VBS-adjacent modules.

## Bridge To Public PoC Reading

Patch diffing and PoC reading should reinforce each other.

Good sequence:

```text
patch diff
  -> likely invariant
  -> read public write-up
  -> compare whether the write-up's claimed bug matches the patch evidence
```

This guards against a common problem:

```text
public PoC exists
  !=
PoC explains the real vulnerability accurately
```

That is especially important for modern Windows write-ups where:

- a blog may skip the exact fix,
- a PoC may rely on one build only,
- a bypass chain may be presented as if it were the root bug,
- the vulnerable condition may be oversimplified.

## Good Patch-Diff Questions For A Repo Note

When you document a patched issue, answer:

1. Which binaries changed and why are they relevant?
2. Which functions are the strongest candidates and why?
3. What invariant appears to be newly enforced?
4. What attacker-controlled path could reach the pre-patch logic?
5. What mitigations or deployment states reduce practical reachability?
6. What would falsify your current hypothesis?

That last question matters. Patch analysis should stay falsifiable.

## Failure Modes In Patch Analysis

### Wrong Binary

You diff a touched binary that is adjacent but not decisive.

### Wrong Baseline

You compare versions from different cumulative-update lines or architectures.

### Tool Over-Trust

You follow similarity ranking mechanically instead of reasoning from subsystem
semantics.

### Semantic Overreach

You infer a memory corruption bug when the patch only strengthens policy state or
error handling.

### Reachability Blindness

You identify a changed function but never prove attacker-controlled input can reach
it.

### Noise Confusion

Compiler churn, refactoring, or telemetry additions are mistaken for the security
fix itself.

## How To Use This Note In The Repo

Use this note when:

- starting from Patch Tuesday and looking for research candidates,
- reading Microsoft advisories that underspecify the root bug,
- validating whether a public exploit story matches binary evidence,
- teaching someone how to move from patch package to candidate invariant.

Recommended follow-up path:

1. `docs/kernel-research/ida-ghidra-driver-re-patterns.md`
2. `docs/kernel-research/public-poc-reading-and-annotation-template.md`
3. `docs/kernel-research/runtime-pdb-symbol-resolution.md`
4. `docs/kernel-research/win32k-case-study-atlas.md`
5. `docs/debugging/windbg-kernel-research-workflow.md`

## Study Questions

1. Why is "which binary changed?" often harder than it sounds?
2. Why are similarity percentages insufficient to classify the security fix?
3. What makes a patch-diff hypothesis strong instead of speculative?
4. How do you separate compiler churn from invariant-relevant changes?
5. Why is reachability analysis mandatory after finding a candidate changed
   function?
6. How would you adapt this workflow from SMB to a third-party signed OEM driver?

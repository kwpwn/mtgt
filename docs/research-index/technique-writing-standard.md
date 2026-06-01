# Technique Writing Standard

## Purpose

Every technique document in this repository should teach the reader how to reason, not just what to memorize. A good note should answer:

```text
What is the technique?
Why does it work?
What assumptions does it need?
What breaks those assumptions?
How do we verify it safely?
How would a defender find inconsistencies?
```

Use this structure for new technical notes.

## Required Structure

### 1. Technique Summary

One short paragraph and one diagram.

Example:

```text
known kernel pointer
  -> find containing PE image
  -> validate headers
  -> recover module base
```

### 2. Required Assumptions

List the assumptions explicitly:

- required privilege or lab context,
- required object or pointer,
- required Windows version or build family,
- required symbol availability,
- required telemetry or debugger visibility,
- what is unknown.

### 3. Why This Works

This is the most important section. Explain the invariant.

Good examples:

- PE images start with `MZ` and contain NT headers at `e_lfanew`.
- A process is not only one list entry; it is a graph of threads, handles, token, address space, and telemetry.
- I/O rings create long-lived relationships among buffers, files, queues, and asynchronous completions.

Avoid:

- "do X because everyone does it",
- copying exploit steps,
- listing offsets without explaining the object model.

### 4. Step-by-Step Reasoning

Use conceptual steps, not weaponized recipe steps.

Good:

```text
1. Identify which view is being trusted.
2. Identify what object graph supports that view.
3. Identify alternate views that do not depend on the same list.
4. Compare results.
```

Bad:

```text
1. Write this field.
2. Patch this pointer.
3. Run this payload.
```

### 5. Ask "Why?" at Each Step

For each major step, include reasoning questions:

| Question | What it proves |
|---|---|
| Why is this pointer trustworthy? | Validates anchor quality |
| Why does this structure own lifetime? | Avoids stale-reference reasoning |
| Why would this view miss the object? | Explains the hide mechanism |
| Why would another view still see it? | Explains detection |
| Why is this build-sensitive? | Prevents false generalization |

### 6. Failure Modes

Document how the technique fails:

- version drift,
- wrong object type,
- stale pointer,
- bad reference count,
- list inconsistency,
- missing symbol,
- protected data,
- telemetry contradiction.

### 7. Defensive Angle

Every offensive-looking technique should have a defensive counterpart:

- what invariant is violated,
- what telemetry records the setup,
- what cross-view comparison exposes the mismatch,
- what policy or mitigation changes the viability.

### 8. Study Questions

End each technique with self-check questions.

Example:

- What must be true before this technique can work?
- What would prove the result is false?
- What alternate data source could confirm or deny the observation?
- Which Windows build facts must be recorded?

## Safety Boundary

Technique notes should not include:

- runnable exploit chains,
- shellcode,
- token stealing code,
- DSE bypass code,
- rootkit hide/unhide implementation code,
- weaponized trigger buffers,
- hardcoded live-target offsets.

Acceptable content:

- object model explanation,
- debugger reasoning,
- PE/header parsing concepts,
- cross-view detection logic,
- mitigation reasoning,
- crash-triage workflow,
- lab-safe pseudocode that does not mutate target security state.

## Example Technique Index Entry

Use this style in indexes:

```text
| Kernel base from LSTAR | `docs/kernel-research/kernel-base-from-lstar-pattern-scan.md` | Interior pointer -> PE base reasoning |
```

The description should name the reasoning pattern, not just the buzzword.

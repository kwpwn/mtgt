# 07 - HVCI and Existing-Code Invocation

Based on Connor McGarr: https://connormcgarr.github.io/hvci/

Last updated: 2026-05-25

## 1. The important correction

Many people say "HVCI bypass" when they mean:

```text
I avoided the thing HVCI protects.
```

HVCI protects kernel code integrity. It tries to prevent unsigned/untrusted kernel code from executing.

It does not promise:

- no data corruption,
- no unsafe signed driver IOCTL,
- no token DKOM,
- no process-kill BYOVD,
- no ROP using existing executable code if other mitigations do not stop it.

## 2. Why shellcode is the wrong default

Without HVCI:

```text
arbitrary write -> PTE tamper -> executable payload -> shellcode
```

With HVCI:

```text
arbitrary write -> PTE tamper
  but secure code integrity / EPT policy may still reject execution
```

So a researcher asks:

```text
What can existing signed kernel code do for me?
```

## 3. Connor's model

The conceptual chain:

```text
arbitrary kernel R/W
  -> create/control dummy thread
  -> leak KTHREAD/kernel stack
  -> place return-oriented chain on kernel stack
  -> resume/trigger thread
  -> execute existing kernel code
  -> cleanup
```

This is not about injecting new code. It is about steering already executable code.

## 4. Why dummy thread

A dummy thread gives:

- isolated kernel stack,
- controllable lifecycle,
- less risk to the current exploit thread,
- a place to build/observe stack state,
- cleanup route.

It also keeps the exploit model cleaner. If the controlled thread dies, the rest of the process can still recover/report.

## 5. Why KTHREAD matters

`KTHREAD` links user-visible thread state to kernel scheduler/thread internals, including stack-related fields. If arbitrary R/W can identify a thread's kernel object and stack, the attacker can reason about return addresses and frame layout.

Research caveats:

- Exact fields are version-sensitive.
- Stack layout is context-sensitive.
- A wrong overwrite can bugcheck.
- CET shadow stack changes viability.

## 6. Why kCFG is not enough

Connor's method uses returns. kCFG checks indirect calls/jumps. Therefore kCFG is not the primary blocker.

Primary blocker:

```text
CET/kernel shadow stack
```

because it protects return-address integrity.

## 7. Windows-current mitigation picture

On Windows 11 24H2/25H2-era targets:

- HVCI on: unsigned kernel code execution is difficult.
- kCFG on: function pointer hijack is constrained.
- CET kernel shadow stack on: ROP/return overwrite is constrained.
- KDP: selected data corruption is constrained.
- WDAC/blocklist: known vulnerable drivers may not load.

Therefore stable chains prefer:

- data-only object/state changes,
- allowed signed driver semantics,
- legitimate kernel API paths,
- existing-code invocation only when the CET state permits.

## 8. Relation to BYOVD

BYOVD often avoids HVCI's core guarantee:

```text
driver code is signed and executable
driver performs dangerous operation
attacker controls operation parameters
```

HVCI sees signed code executing. The vulnerability is semantic: the signed code should not expose that operation to untrusted callers.

## 9. Research checklist

For any "HVCI bypass" claim:

- Does it execute unsigned bytes?
- Does it only reuse existing signed code?
- Does it corrupt mutable data?
- Is CET/shadow stack enabled?
- Is kCFG relevant?
- Is the target data KDP-protected?
- Is the driver allowed by WDAC/blocklist?
- Is this actually breaking HVCI or just avoiding its scope?

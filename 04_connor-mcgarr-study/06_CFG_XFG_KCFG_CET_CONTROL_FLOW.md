# 06 - CFG, XFG, kCFG and CET Control-Flow Deep Dive

Based on Connor McGarr:

- https://connormcgarr.github.io/examining-xfg/
- https://connormcgarr.github.io/hvci/

Last updated: 2026-05-25

## 1. Two edges: forward and backward

Control-flow mitigations must be separated:

```text
Forward edge:
  indirect call/jmp through function pointer, vtable, callback

Backward edge:
  return from function
```

CFG/XFG/kCFG focus mainly on the forward edge. CET/shadow stack focuses on the backward edge.

This distinction explains many bypasses.

## 2. CFG

CFG asks:

```text
Is this indirect call target a valid target?
```

It blocks simple function pointer overwrites to arbitrary gadgets. But it is coarse. If the target is a valid function entry, CFG may allow it even if the callsite expected a different prototype.

## 3. XFG

XFG adds type/prototype awareness. It asks:

```text
Is target valid?
Does target match expected function type hash?
```

This reduces the target set. An attacker cannot simply point a callback at any valid function; they need a compatible target.

## 4. kCFG

kCFG applies CFG-style thinking in the kernel. It is relevant for:

- function pointer overwrite,
- vtable-style dispatch,
- callback table corruption,
- driver object dispatch abuse,
- indirect call target abuse.

It is not the main blocker for:

- return-address overwrite,
- token DKOM,
- `PreviousMode` DKOM,
- process-kill IOCTL.

## 5. CET / shadow stack

CET shadow stack protects returns:

```text
CALL:
  push return to normal stack
  push return to shadow stack

RET:
  compare normal return with shadow return
```

If an attacker overwrites only the normal return address, a mismatch occurs.

This is why Connor's HVCI ROP chain is naturally pressured by kernel-mode hardware-enforced stack protection.

## 6. Why Connor's HVCI chain avoided kCFG

Connor's HVCI approach uses return-oriented control of existing code, not arbitrary indirect call target hijack.

Therefore:

```text
kCFG: less directly relevant
CET: directly relevant
```

This is the key mental model:

- If the exploit overwrites a callback/function pointer -> ask kCFG/XFG.
- If the exploit overwrites a return address -> ask CET/shadow stack.
- If the exploit overwrites a data field -> ask KDP/PatchGuard/object semantics.

## 7. Bypass thinking

CFG/kCFG bypass classes:

- Use a valid target.
- Use a semantically useful valid target.
- With XFG, use a compatible-type target.
- Avoid indirect call hijack.
- Use the data-only route.

CET bypass classes at the concept level:

- Avoid return-address corruption.
- Use a legitimate call path.
- Use the data-only route.
- Find a path where the shadow stack is synchronized, disabled, unsupported, or not covering that context.

Modern exploit engineering often chooses:

```text
data-only > existing-code call path > ROP > raw shellcode
```

when HVCI/CET/kCFG are active.

## 8. Why XFG matters beyond user mode

Connor's XFG article is about user-mode compiler mitigation, but the research lesson transfers:

```text
valid address is not enough;
valid semantic type matters.
```

Kernel CFI follows the same broad direction. Future exploit targets need to be both reachable and type/semantic-compatible.

## 9. Research checklist

For a control-flow exploit:

- Is control forward-edge or backward-edge?
- Is CFG/kCFG enabled?
- Is XFG compiled in for the target module?
- Is CET/shadow stack enabled?
- Is the target a valid function start?
- Is the prototype/type compatible?
- Does the chain need ROP?
- Can the chain be changed to data-only?
- Is PatchGuard watching the target?

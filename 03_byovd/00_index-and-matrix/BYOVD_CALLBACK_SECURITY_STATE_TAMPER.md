# BYOVD Callback and Security-State Tamper Primitives

Updated: 2026-05-27

## Technique Summary

Some BYOVD chains use kernel R/W to modify security product state or kernel callback registration state.

Companion case studies:

- `BYOVD_CASE_RTCORE64.md`
- `BYOVD_CASE_GDRV.md`
- `BYOVD_CASE_DBUTIL_2_3.md`
- `BYOVD_PROCESS_CREATE_CALLBACK_TAMPER_S12DEFF.md`

```text
vulnerable driver gives kernel write
  -> target callback/security state
  -> monitoring or protection weakens
  -> attacker performs later action with less visibility
```

This class is powerful but fragile. It is closer to rootkit tradecraft than simple LPE, so this document focuses on reasoning, invariants, and detection.

## Representative Context

Sources and public context:

- EDRSandblast uses vulnerable-driver kernel R/W concepts against EDR callback-related state:
  https://github.com/wavestone-cdt/EDRSandblast
- Threat intel reports repeatedly describe BYOVD against callback/security telemetry using `RTCore64.sys`, `gdrv.sys`, and `DBUtil_2_3.sys`.
- Repo-local callback notes:
  `docs/kernel-research/callback-surfaces.md`

## Required Assumptions

Callback/security-state tamper needs:

- arbitrary or targeted kernel write,
- target callback/security structure known for the Windows build,
- owner module and callback registration understood,
- ability to avoid PatchGuard-sensitive corruption,
- ability to avoid immediate crash,
- telemetry gap worth the risk.

This is not a good first impact choice. It is usually chosen when the goal is defense evasion rather than simple privilege escalation.

## Why This Works

Windows and security products use callback registration systems:

```text
driver registers callback
  -> kernel stores callback state
  -> event occurs
  -> kernel invokes registered callback
```

Examples:

- process creation notification,
- thread creation notification,
- image load notification,
- object handle callbacks,
- registry callbacks,
- minifilter callbacks,
- filesystem/network inspection,
- security product private state.

If a vulnerable write corrupts or disables that state, visibility or enforcement can change.

## Process-Creation Callback Tamper Case

S12Deff's "Overwriting Process Creation Kernel Callbacks" article fits here:

```text
BYOVD kernel read/write
  -> process-notification callback registration state
  -> process-birth observer mismatch
```

The important classification is callback/security-state tamper, not standalone
LPE. The technique assumes a kernel write primitive already exists. The write is
used to change whether the process creation dispatch path reaches the observer
that a security driver expects.

Why this is a distinct case:

- process creation is an early lineage event,
- many EDR correlation graphs start at process birth,
- process callbacks are OS-mediated, not product-private hooks,
- the target state is build-sensitive private kernel state,
- success produces partial telemetry desynchronization, not universal invisibility.

Local deep dive:

- `BYOVD_PROCESS_CREATE_CALLBACK_TAMPER_S12DEFF.md`

Compare it with nearby families:

| Family | Surface | What weakens |
|---|---|---|
| process-create callback tamper | process notification registration state | process-birth telemetry |
| thread callback tamper | thread notification registration state | remote-thread and thread lifecycle telemetry |
| image callback tamper | image-load notification state | module/image load telemetry |
| object callback tamper | Object Manager callback lists | handle access filtering and observation |
| minifilter unlinking | Filter Manager callback/list state | file I/O telemetry |
| WFP callout tamper | WFP callout/classify state | network telemetry |
| ETW TI state tamper | kernel ETW provider state | kernel-native behavior events |

## What It Can Do

Possible effects:

- remove selected security visibility,
- interfere with process/image monitoring,
- weaken handle protection,
- disrupt registry or file callbacks,
- blind EDR sensor logic,
- crash the system,
- trigger tamper protection or PatchGuard.

Important:

```text
callback tamper is usually not stealthy if defenders correlate before/after telemetry
```

## Why It Is Fragile

Callback state has multiple risks:

- callback arrays/lists can be guarded,
- function pointers must remain valid,
- owner modules must remain loaded,
- PatchGuard may monitor some structures,
- EDR may self-check callback presence,
- removing one callback may not disable product visibility,
- wrong write causes immediate bugcheck.

Question:

```text
What invariant is being violated, and who checks it?
```

If the answer includes PatchGuard, EDR self-protection, or kernel verifier, risk is high.

## Technique Reasoning Flow

### Step 1: Identify security surface

Ask:

- Is this process, image, object, registry, file, or network visibility?
- Is it OS-owned or EDR-owned?
- Is it callback-driven, filter-driven, or private driver state?

### Step 2: Identify owner

Ask:

- Which module registered it?
- Is the callback pointer inside a valid loaded image?
- Is the module still loaded?
- Does the product have backup visibility elsewhere?

### Step 3: Identify expected consistency

Ask:

- Should this product have callbacks registered when its service is running?
- Does callback absence contradict service/process state?
- Does driver-load telemetry show a vulnerable R/W driver just before the absence?

### Step 4: Compare before/after telemetry

Detection is often temporal:

```text
driver load
  -> vulnerable driver IOCTL activity
  -> callback inventory changes
  -> EDR visibility drops
  -> attacker action follows
```

## Defensive Cross-View Checks

| Expected state | Suspicious mismatch |
|---|---|
| EDR service running | expected callbacks missing |
| callback pointer present | pointer outside known module range |
| callback owner module loaded | callback points to unloaded memory |
| driver-load telemetry normal | vulnerable R/W driver loaded immediately before telemetry loss |
| process/image events steady | sudden gap after vulnerable driver activity |

## Relationship to PatchGuard

PatchGuard exists partly to detect unauthorized kernel tampering. Not every callback or private product state is equally protected, but callback tamper lives close to monitored territory.

Practical reasoning:

```text
the more global and persistent the tamper,
the more likely it is to be detected or crash later
```

Short-lived tamper can reduce exposure but increases timing complexity.

## Relationship to HVCI

HVCI does not automatically prevent data-only writes to mutable callback state if the vulnerable driver can write there. But it does reduce classic alternatives like injecting unsigned executable kernel code.

So HVCI can push attackers toward data/state tamper while still making stable exploitation harder.

## Detection Angle

Hunt for:

- vulnerable R/W driver load,
- sudden EDR callback disappearance,
- callback pointer outside known module ranges,
- security service still running but telemetry silent,
- minifilter unloaded unexpectedly,
- process/image/registry telemetry gap after driver load,
- crash dumps involving callback lists,
- service-control events around security products.

## Failure Modes

- PatchGuard bugcheck,
- EDR self-defense detects tamper,
- product restores callback,
- wrong callback slot modified,
- pointer validation fails,
- callback still registered through another path,
- telemetry loss itself becomes an alert,
- target layout changed by update.

## Study Questions

- What security event is being blinded?
- Which callback/filter system observes it?
- Which module owns the callback?
- What data structure stores the registration?
- Which independent view can confirm callback absence?
- What would PatchGuard or EDR self-check notice?
- Is the goal worth more than a simpler data-only impact?

## Summary

Callback/security-state tamper is not just "write null somewhere." It is consistency manipulation:

```text
security product should observe event
  -> callback/filter state changes
  -> observation weakens
  -> cross-view telemetry can reveal the contradiction
```

Treat this primitive as high-risk, noisy, and detection-rich.

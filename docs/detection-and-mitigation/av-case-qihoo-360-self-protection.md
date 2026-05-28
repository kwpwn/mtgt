# Qihoo / 360 Self-Protection Case Study

Updated: 2026-05-27

## Classification

Qihoo / 360 Total Security self-protection research in this repo is classified as:

```text
AV self-protection driver dependency research
  -> product driver enforces runtime protection
  -> startup and service policy determine whether the driver is present
  -> if the driver is absent, higher-level self-protection may collapse
```

This is different from Huorong's public prompt/IPC cases and different from
Defender's trusted broker/quarantine consistency case.

Primary product reference:

- https://www.360totalsecurity.com/en/features/360-total-security/

Historical research reference:

- The Antivirus Hacker's Handbook, O'Reilly:
  https://www.oreilly.com/library/view/the-antivirus-hackers/9781119028758/

## Product Shape

360 Total Security is a security suite with real-time protection and multiple
engines/features. Historical self-protection discussion centers on a product
driver responsible for defending product processes and components from local
tamper.

The simplified model:

```text
product services and UI
  -> self-protection driver
  -> process/file/registry/service protection
```

The driver is the enforcement anchor. If the driver is present and working, the
product can block many direct local tamper actions. If the driver is absent at
boot, the user-mode product components may still exist but the self-protection
anchor is missing.

## Historical Driver-Startup Dependency Case

The Antivirus Hacker's Handbook discusses a historical Qihoo 360 self-protection
case where weakening the startup path for the self-protection driver prevents the
driver from loading after reboot.

The repo does not reproduce the operational registry path or exact values. The
research classification is enough:

```text
startup policy tamper
  -> self-protection driver does not load
  -> runtime self-protection expectations no longer hold
```

## Broken Invariant

Expected invariant:

```text
if the product is installed and enabled,
self-protection driver should be present before user-mode product attack surface
is exposed
```

Historical pressure:

```text
local startup configuration can prevent the self-protection driver from loading
```

The deeper invariant:

```text
self-protection cannot depend only on a mutable startup flag
```

If the product trusts "driver loaded" as a runtime fact but does not sufficiently
protect the condition that makes the driver load, self-protection has a boot-time
gap.

## Why This Class Matters

Runtime driver self-protection can be strong after it is loaded:

```text
driver loaded
  -> product process/file/registry accesses are mediated
```

But boot and service configuration happen before or around the point where the
driver becomes active:

```text
boot configuration
  -> driver load decision
  -> runtime protection
```

That means the driver's own loadability is part of the security boundary.

This is similar to asking:

```text
who protects the protector before it starts?
```

## Difference From BYOVD

This case is not BYOVD by itself.

BYOVD:

```text
attacker brings a vulnerable signed driver
  -> obtains kernel primitive or privileged action
```

360 self-protection startup dependency:

```text
installed AV driver is supposed to protect product
  -> startup/load condition is modified
  -> protection anchor absent on next boot
```

Both involve drivers, but the trust direction is opposite:

- BYOVD abuses a vulnerable helper driver.
- 360 startup dependency weakens the product's own protection driver.

## Difference From Huorong

Huorong public cases:

```text
driver is active
  -> trusts weak UI/IPC/process coverage
```

360 historical startup case:

```text
driver is not active
  -> product loses protection anchor
```

Huorong teaches decision-channel trust. 360 teaches boot/load anchoring.

## Difference From Defender

Defender's Windows-integrated self-protection uses OS-level protected service
concepts, Code Integrity, ELAM registration, Tamper Protection, and minifilter
behavior.

360's historical case is better understood as:

```text
product-specific driver must load
  -> driver load condition must be protected
```

Defender's Medium case is a trusted-broker problem. The 360 case is a
pre-enforcement availability problem.

## Research Matrix

| Question | Why It Matters |
|---|---|
| Which 360 driver enforces self-protection on this version? | Product suites may change component names and split responsibilities. |
| Is the driver boot-start, system-start, demand-start, or product-managed? | Startup timing determines the pre-protection window. |
| What protects the driver's service configuration? | Mutable startup policy is a high-value tamper point. |
| Does the product detect that the self-protection driver failed to load? | Failure should create an unhealthy state, not silent reduced protection. |
| Does the product repair driver startup settings? | Repair behavior controls persistence of the tamper. |
| Does Safe Mode/offline modification change behavior? | Self-protection may be absent outside normal boot. |
| Are there multiple drivers with overlapping protection roles? | Disabling one driver may not disable the whole product. |

## Safe Lab Reading Notes

When studying old 360 writeups, avoid assuming current versions share the same
layout. Instead, document:

```text
version
driver inventory
service start type
who owns the service key
whether product self-repairs
whether product health notices missing driver
whether Windows Security Center still sees the product as healthy
```

The useful outcome is not "how to disable 360." The useful outcome is a model:

```text
self-protection depends on boot-time anchors
```

## Common Failure Modes For Driver-Dependency Self-Protection

- Product update changes driver name or load order.
- Multiple drivers enforce overlapping policy.
- Watchdog service restores startup settings.
- Product cloud health flags missing self-protection.
- Windows policy or Secure Boot changes driver load behavior.
- Driver starts later than expected, creating a short local gap.
- Driver load fails but product UI still reports a healthy state.

The last item is the most interesting research condition:

```text
driver absent
  + product says protected
  -> health-state contradiction
```

## Study Questions

1. Why is driver startup configuration part of the security boundary?
2. What should a product do if its self-protection driver is missing?
3. Why is "product process is running" weaker than "product enforcement driver is
   loaded and healthy"?
4. What is the difference between disabling a product's own protection driver and
   abusing a vulnerable third-party driver?
5. How should health reporting represent a missing self-protection anchor?
6. Which state should be checked after reboot: service state, driver object,
   device object, product UI, Windows Security Center, or backend health?

## References

- 360 Total Security official feature page:
  https://www.360totalsecurity.com/en/features/360-total-security/
- The Antivirus Hacker's Handbook, O'Reilly:
  https://www.oreilly.com/library/view/the-antivirus-hackers/9781119028758/
- Driver-load and Code Integrity repo note:
  `docs/detection-and-mitigation/driver-load-etw-and-code-integrity.md`
- AV self-protection index:
  `docs/detection-and-mitigation/av-self-protection-research-index.md`

# Microsoft Defender Self-Protection Case Study

Updated: 2026-05-27

## Classification

Microsoft Defender self-protection research in this repo is split into three
separate buckets:

```text
Defender self-protection
  -> protected antimalware service model
  -> Tamper Protection and policy control
  -> minifilter-backed file protection
  -> trusted management and quarantine flows
  -> state/update consistency attacks
```

The important distinction:

```text
Defender bypass via trusted product path
  != BYOVD
  != arbitrary kernel read/write
  != DSE bypass
```

The Medium article by Daniel Santos is best classified as:

```text
trusted broker / quarantine restore consistency issue
```

SNEK Equinox is best classified as:

```text
state spoofing + signature/update file-lock interference
```

## Defender Self-Protection Layers

Defender is not one process and one driver. It has several protection layers:

| Layer | Research role |
|---|---|
| AM-PPL / protected service model | Raises the bar for process injection, untrusted DLL loading, and direct tamper |
| ELAM-backed registration | Lets Windows validate antimalware service launch protection |
| Code Integrity | Restricts what can load into protected antimalware processes |
| WdFilter-style file-system protection | Protects selected Defender paths from normal modification |
| Tamper Protection | Blocks many direct local configuration changes |
| Product management tools | Legitimate control plane for scan, update, restore, and maintenance operations |
| Quarantine and restore flow | Trusted product broker that can move content in privileged product context |
| Cloud/MDE reporting | May compute health from product telemetry rather than simple local fields |

Why this matters:

```text
a layer can be correct in isolation
but a trusted path can cross the layer boundary
```

For self-protection research, the interesting bugs are usually in those crossings.

## Case 1: Quarantine Restore As Trusted Broker

Source:

- https://vovohelo.medium.com/bypassing-defenders-self-protect-mechanism-3b860301fb07

### What The Public Writeup Describes

The article studies Defender's official command-line management surface and then
focuses on the quarantine restore workflow. The important observation is not
"Defender has a command-line tool." The important observation is:

```text
the restore operation is handled by Defender's own trusted engine context
```

That changes the trust relationship:

```text
untrusted external process cannot normally write to protected product path
trusted Defender restore broker may be allowed to write there
```

The article then reasons about a destination/path consistency issue: a file that
was quarantined can be restored through a trusted product path into a location
that normal callers should not be able to modify.

### Broken Invariant

Expected invariant:

```text
protected product folder
  -> cannot be modified by untrusted local admin or SYSTEM paths
```

Observed research pressure:

```text
trusted product broker
  -> performs a restore operation
  -> destination policy may be weaker than direct write policy
```

The deeper invariant is:

```text
privileged product repair/restore flows must enforce the same destination trust
policy as direct file writes
```

### Why It Can Work

The technique does not need to break PPL directly. It tries to make the protected
product perform the sensitive action itself.

The chain is conceptually:

```text
external caller asks product broker to restore content
  -> broker has product trust
  -> broker writes into a product-relevant location
  -> product restart/load path sees unexpected content
```

This is a classic confused-deputy shape:

```text
caller lacks direct authority
but deputy has authority
and deputy does not preserve the caller's security context strongly enough
```

### What It Is Not

It is not:

- a kernel exploit,
- arbitrary file-system write,
- a generic Defender disable primitive,
- proof that every current Defender build behaves the same way,
- proof that MDE cloud health will accept the local state as true.

It is a product-flow consistency case.

### Failure Modes

This kind of technique is brittle because each assumption can change:

- the quarantine restore implementation may validate destinations more strictly;
- the protected folder policy may add explicit denial for restore paths;
- the product may repair or delete unexpected content on restart;
- Code Integrity may reject unexpected module content;
- platform version changes may alter load behavior;
- Tamper Protection and cloud policy may block or repair the chain;
- backend health may mark the endpoint unhealthy even if local UI state is odd.

## Case 2: SNEK Equinox State And Signature Consistency

Source:

- https://github.com/The-SNEK-Initiative/SNEK_Equinox

Detailed repo note:

- `docs/detection-and-mitigation/av-edr-user-mode-tamper-spoofing.md`

SNEK Equinox uses a different model from the Medium quarantine case.

Its pressure pattern:

```text
local state/version metadata looks healthy
  + selected signature/update files are locked or racing
  -> state and actual signature usability may diverge
```

Broken invariant:

```text
reported product health should match real engine/update health
```

This is not a direct self-protection bypass. It is a consistency attack between:

- registry state,
- version metadata,
- update/signature file availability,
- service state,
- console or cached reporting state.

## Defender Internals Questions

When reading Defender research, separate these questions:

### Who Is The Actor?

```text
external admin process
Defender command-line tool
Defender engine process
Defender service
Defender minifilter
MDE backend
```

The same file action means different things depending on who performs it.

### What Is The Object?

```text
service state
process protection state
protected folder content
signature database
quarantine item
registry policy
cloud health report
```

Do not say "Defender is bypassed" without naming the object.

### Which Trust Boundary Is Crossed?

Common boundaries:

```text
external process -> product management tool
management tool -> engine service
engine service -> protected folder
quarantine store -> restore destination
local registry -> backend health
```

Each boundary needs a different validation model.

## Research Matrix

| Research case | Primitive type | Broken invariant | Persistence shape |
|---|---|---|---|
| Quarantine restore case | trusted broker destination confusion | protected location policy should apply to restore path | may survive until repair/update/restart cleanup |
| SNEK Equinox registry state | state spoofing | local product state should reflect real protection | persists until product rewrites state |
| SNEK Equinox file locks | update/signature interference | signature availability should match version metadata | live while lock-holding process runs |
| Direct config tamper | policy/config change | local admin should not override protected policy when Tamper Protection is active | depends on policy and management channel |
| BYOVD against Defender | kernel primitive or privileged driver action | OS security object or callback state changes | depends on driver primitive and mitigation state |

## Why "Admin Required" Still Matters

Many public Defender tamper writeups assume local administrator rights. That does
not make them irrelevant, but it changes the classification.

With admin rights, the research question becomes:

```text
which protections still hold against a local administrator?
```

Defender self-protection exists partly because malware often reaches local admin
but should still not be able to trivially turn off antimalware protection. A
trusted-broker bypass is interesting because it uses a product-approved path
rather than a raw delete or process kill.

## Study Questions

1. Why is "trusted Defender component wrote the file" different from "attacker
   wrote the file"?
2. What should a quarantine restore broker validate before writing a file?
3. Why does PPL not automatically solve every product-flow bug?
4. Which state is authoritative: local registry, protected service, signature
   load state, or cloud/MDE health?
5. What does a reboot change in a restore/load consistency issue?
6. Why is SNEK Equinox live-file-lock behavior weaker than persistent product
   configuration tamper?

## References

- Daniel Santos, "Bypassing Defender's self-protect mechanism":
  https://vovohelo.medium.com/bypassing-defenders-self-protect-mechanism-3b860301fb07
- Microsoft, Protecting anti-malware services:
  https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-
- Microsoft, Tamper Protection:
  https://learn.microsoft.com/en-us/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection
- Microsoft, Defender command-line reference:
  https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus
- SNEK Equinox:
  https://github.com/The-SNEK-Initiative/SNEK_Equinox

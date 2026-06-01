# Windows Kernel Pwn Question Bank

Backlinks: [README](../../README.md) | [topic index](topic-index.md) | [learning path](windows-kernel-pwn-learning-path.md)

## Beginner

| Question | Why important | Hint | Links |
|---|---|---|---|
| What is the difference between a handle and a kernel object pointer? | Many leaks confuse the two. | Handle is process-scoped; object pointer is kernel address. | [primitive framework](../kernel-research/primitive-reasoning-framework.md) |
| Why does a driver create a device object and symbolic link? | This is the user/kernel entry point. | Look for `\Device\` and `\DosDevices\`. | [IOCTL workflow](../userland-to-kernel/ioctl-reversing-workflow-deep-dive.md) |
| What does `CTL_CODE` encode? | It predicts buffer handling and access. | Device type, function, method, access. | [IOCTL workflow](../userland-to-kernel/ioctl-reversing-workflow-deep-dive.md) |
| Why is `METHOD_NEITHER` risky? | Raw user pointers cross into kernel logic. | Probe, lock, and TOCTOU issues. | [IOCTL workflow](../userland-to-kernel/ioctl-reversing-workflow-deep-dive.md) |
| What is CR3? | Address translation starts here. | It points to the active paging root. | [page tables](../windows-internals/page-table-and-address-translation-deep-dive.md) |

## Intermediate

| Question | Why important | Hint | Links |
|---|---|---|---|
| Why is physical R/W not automatically arbitrary virtual R/W? | Many BYOVD chains depend on translation. | Need CR3, page walk, page size, PFN. | [page tables](../windows-internals/page-table-and-address-translation-deep-dive.md) |
| What makes arbitrary decrement dangerous? | Weak primitives can affect trust fields. | PreviousMode is a classic reasoning target. | [primitive framework](../kernel-research/primitive-reasoning-framework.md) |
| Why can a valid signed driver still be dangerous? | BYOVD abuses trust in signed code. | Signature authenticates origin, not behavior. | [BYOVD threat model](../byovd/byovd-modern-windows-11-threat-model.md) |
| How does KVA shadow affect syscall-entry thinking? | Early transition state is constrained. | User and kernel page-table views differ. | [page tables](../windows-internals/page-table-and-address-translation-deep-dive.md) |
| Why do pool overflows need target-object reasoning? | Overflow alone is not control. | Need adjacency, field effect, and stability. | [pool map](../windows-heap/kernel-pool-exploitation-study-map.md) |

## Advanced

| Question | Why important | Hint | Links |
|---|---|---|---|
| Why does HVCI break PTE-based shellcode assumptions? | Modern Windows protects code integrity outside VTL0. | PTE execute bit is not enough. | [mitigation deep dive](../mitigations/hvci-vbs-kdp-vtrp-hlat-deep-dive.md) |
| How does HLAT change remapping-attack reasoning? | Guest page-table tamper may be ignored. | Hypervisor-managed translation wins for protected ranges. | [mitigation deep dive](../mitigations/hvci-vbs-kdp-vtrp-hlat-deep-dive.md) |
| Why is existing-code invocation still relevant under HVCI? | Code integrity does not equal behavior integrity. | Reusing signed code can still be powerful. | [mitigation deep dive](../mitigations/hvci-vbs-kdp-vtrp-hlat-deep-dive.md) |
| What makes PatchGuard hard to reason about? | Failure may be delayed and nondeterministic. | No crash now does not prove no violation. | [primitive framework](../kernel-research/primitive-reasoning-framework.md) |
| Why are dynamic PDB-derived offsets not a safety guarantee? | They reduce offset drift but not policy or consistency risk. | Correct address can still be a protected/bad target. | [case-study matrix](case-study-matrix.md) |

## Case-Study Reasoning

| Question | Why important | Hint | Links |
|---|---|---|---|
| What problem does the source solve? | Prevents reading it as a recipe. | State the research question in one sentence. | [case-study matrix](case-study-matrix.md) |
| What is only true on the tested build? | Build drift breaks conclusions. | Look for offsets, SKU, HVCI state, CPU. | [source status](source-integration-status.md) |
| What primitive is actually achieved? | Avoids overclaiming. | Use the scorecard. | [primitive framework](../kernel-research/primitive-reasoning-framework.md) |
| What is the first mitigation that breaks the chain? | Teaches defensive leverage. | HVCI, KCFG, KDP, blocklist, Secure Boot. | [mitigation deep dive](../mitigations/hvci-vbs-kdp-vtrp-hlat-deep-dive.md) |
| What telemetry appears before impact? | Detection often starts early. | Driver load, device open, IOCTLs, crashes. | [detection playbook](../detection-and-mitigation/byovd-detection-engineering-playbook.md) |

## Mitigation Reasoning

| Question | Why important | Hint | Links |
|---|---|---|---|
| Does the target system have HVCI enabled? | End state changes. | Memory Integrity UI/registry/policy. | [mitigation deep dive](../mitigations/hvci-vbs-kdp-vtrp-hlat-deep-dive.md) |
| Does Secure Boot matter here? | Enables stronger driver trust assumptions. | It interacts with CI and blocklists. | [BYOVD threat model](../byovd/byovd-modern-windows-11-threat-model.md) |
| Is the vulnerable driver blocklist current? | Known-bad drivers may load if stale/off. | Check policy and CI logs. | [detection playbook](../detection-and-mitigation/byovd-detection-engineering-playbook.md) |
| Is the attack data-only or code-execution oriented? | Different mitigations apply. | HVCI blocks unsigned code, not every data write. | [primitive framework](../kernel-research/primitive-reasoning-framework.md) |
| Is target data KDP-protected? | VTL0 writes may fail. | Identify whether data is hypervisor protected. | [mitigation deep dive](../mitigations/hvci-vbs-kdp-vtrp-hlat-deep-dive.md) |

## Detection Reasoning

| Question | Why important | Hint | Links |
|---|---|---|---|
| What is the driver’s normal enterprise prevalence? | Rare drivers deserve priority. | Baseline signer/hash/path. | [detection playbook](../detection-and-mitigation/byovd-detection-engineering-playbook.md) |
| Was the driver loaded from an expected path? | Staging path is high signal. | User-writable paths are suspicious. | [detection playbook](../detection-and-mitigation/byovd-detection-engineering-playbook.md) |
| Which process opened the device object? | Links user intent to kernel capability. | Process lineage matters. | [IOCTL workflow](../userland-to-kernel/ioctl-reversing-workflow-deep-dive.md) |
| Were there kernel crashes near the activity? | Failed probing is telemetry. | Bugcheck stack and driver name. | [pool map](../windows-heap/kernel-pool-exploitation-study-map.md) |
| Did sensitive process state change after load? | BYOVD often precedes tamper. | PPL/token/security-service anomalies. | [BYOVD threat model](../byovd/byovd-modern-windows-11-threat-model.md) |

## Version-Diff Reasoning

| Question | Why important | Hint | Links |
|---|---|---|---|
| Does this rely on a kernel leak removed in 24H2? | Modern builds remove old enablers. | Check source caveats. | [case-study matrix](case-study-matrix.md) |
| Does PreviousMode behavior differ after 22H2? | Public claims are build-specific. | Look for bugcheck/mitigation notes. | [primitive framework](../kernel-research/primitive-reasoning-framework.md) |
| Does CPU generation affect VT-rp/HLAT? | Hardware features are not universal. | 12th+ gen Intel subset claim. | [mitigation deep dive](../mitigations/hvci-vbs-kdp-vtrp-hlat-deep-dive.md) |
| Does Server SKU enable the same defaults? | Enterprise posture differs. | Verify Secure Boot/VBS/HVCI/WDAC. | [learning path](windows-kernel-pwn-learning-path.md) |
| Does the driver version differ from the write-up? | Blocklists and vulnerabilities are version-specific. | Compare signer, timestamp, hash, product version. | [BYOVD threat model](../byovd/byovd-modern-windows-11-threat-model.md) |

# Remaining Work

Backlinks: [README](../../README.md) | [repo audit](repo-audit.md) | [source coverage](source-coverage-report.md)

## Tooling Blockers

Automated shell verification failed after initial directory listing with:

```text
windows sandbox: spawn setup refresh
```

Because of that, this pass could not complete:

- Exact Markdown count.
- Automated dead-link scan.
- Duplicate title grep.
- TODO grep.

## High-Value Next Work

| Priority | Work | Why |
|---|---|---|
| High | Run Markdown link checker | Ensure new cross-links and existing links are clean. |
| High | Review and cross-link older docs | Existing content likely has useful material that should point to new hubs. |
| High | Verify MSRC data for CVE-2026-21222 | Current source is AI/forum-like and low confidence. |
| Medium | Add official Microsoft references for HVCI, blocklist, WDAC, ETW | Improves source quality. |
| Medium | Build version matrix from lab VMs | Avoid relying on PoC offset claims. |
| Medium | Add Sigma/KQL examples at behavioral level | Detection playbook can become operational without evasion content. |
| Low | Merge duplicate glossary definitions from older docs | Reduce drift. |

## Source-Specific Follow-Up

| Source | Follow-up |
|---|---|
| UnknownCheats HVCI forum | Blocked/unsafe; do not integrate unless a safer secondary analysis exists. |
| pwn2nimron blog | Fetch failed; identify specific post URLs and topic. |
| kernullist hiding on Windows | Fetch failed; verify if URL moved or was removed. |
| WindowsForum CVE-2026-21222 | Validate against MSRC before treating as real technical detail. |
| G3tSyst3m LSASS | Keep as defensive case study only; do not copy operational content. |

## Assumptions to Revisit

- Whether Windows 11 25H2 claims in public blogs are accurate for released builds.
- Whether VT-rp/HLAT is used by a given Windows/Hyper-V configuration.
- Whether vulnerable driver blocklist state is enabled by default on all target SKUs.

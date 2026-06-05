# ComoDoS Comodo Inspect.sys Learning Sources

Backlinks: [topic index](topic-index.md) | [case-study matrix](case-study-matrix.md) | [source integration status](source-integration-status.md)

## Source Metadata

| Field | Value |
|---|---|
| Primary source | https://malwaretech.com/2026/06/exploiting-a-remote-kernel-vulnerability-in-comodo-internet-security.html |
| Public title | ComoDoS - Exploiting a Remote Kernel Vulnerability in Comodo Internet Security |
| Author/org | Marcus Hutchins / MalwareTech |
| Published | 2026-06-03 |
| Product | Comodo Internet Security |
| Component claim | Firewall driver, reported as `Inspect.sys` by secondary reporting |
| Bug class | Remote network-triggered kernel crash / denial of service claim |
| Input family | IPv6 packet-processing path claim |
| Trust | Researcher primary post is credible, but direct fetch returned 403 here; vendor advisory/CVE was not confirmed in this pass |
| Status | `needs-review` |

## Why This Belongs In The Repo

This case is useful for learning kernel network-filtering risk:

- third-party AV/firewall products can add kernel network attack surface,
- WFP callouts and NDIS filters must treat packet metadata and buffers as hostile input,
- IPv6 extension headers, fragmentation, and header-data split are common parser edge cases,
- remotely triggered kernel crashes need careful dump attribution before claims are repeated,
- zero-day reporting without vendor acknowledgement needs explicit confidence labels.

Use this as a defensive triage case, not as an exploit reconstruction target.

## Current Claim State

Public metadata says the MalwareTech post describes a still-unpatched issue at publication time and that a report, root-cause analysis, patch suggestions, and a PoC had been sent to Comodo without acknowledgement. SOC Defenders summarizes the issue as a zero-day in the Comodo Internet Security firewall driver. MalwareTips discussion quotes the disclosure context and is useful mainly as a secondary pointer.

Until Comodo publishes an advisory or a CVE is assigned, record the case as:

```text
credible public research claim
  -> affected build unknown
  -> fixed build unknown
  -> vendor confirmation missing
  -> safe action: monitor updates and study WFP/NDIS triage
```

## Recommended Sources

Primary and near-primary:

- MalwareTech primary post: https://malwaretech.com/2026/06/exploiting-a-remote-kernel-vulnerability-in-comodo-internet-security.html
- SOC Defenders metadata summary: https://www.socdefenders.ai/item/671bc39e-b96c-4dc1-ae46-4bc0ce01b3ea
- MalwareTips discussion and quote of disclosure context: https://malwaretips.com/threads/comodo-exploited-comodos-exploiting-a-remote-kernel-vulnerability-in-comodo-internet-security.141655/

Windows network driver fundamentals:

- Microsoft, About Windows Filtering Platform: https://learn.microsoft.com/en-us/windows/win32/fwp/about-windows-filtering-platform
- Microsoft, Introduction to WFP callout drivers: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/introduction-to-windows-filtering-platform-callout-drivers
- Microsoft, Callout driver programming considerations: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/callout-driver-programming-considerations
- Microsoft, Filtering layer: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/filtering-layer
- Microsoft, Processing classify callouts asynchronously: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/processing-classify-callouts-asynchronously
- Microsoft, NDIS filter drivers: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/ndis-filter-drivers
- Microsoft, Splitting IPv6 frames: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/splitting-ipv6-frames

Debugging and triage:

- CodeMachine, Finding Windows Filtering Platform callouts: https://codemachine.com/articles/find_wfp_callouts.html
- Repo note: [WinDbg kernel research workflow](../debugging/windbg-kernel-research-workflow.md)
- Repo note: [driver-load ETW and Code Integrity](../detection-and-mitigation/driver-load-etw-and-code-integrity.md)
- Repo note: [minifilter and EDR visibility](../detection-and-mitigation/minifilter-and-edr-visibility.md)

Product background:

- Comodo help, security alerts and firewall/HIPS behavior: https://help.comodo.com/topic-72-1-766-9044-Understand-Security-Alerts.html
- Comodo forum thread noting `Inspect` as Comodo Firewall Network Driver in service state: https://forums.comodo.com/t/how-do-i-get-comodo-completely-off-my-system/228374
- Comodo historical update on Project Zero-reported security fixes: https://blog.comodo.com/comodo-news/comodo-makes-updates-to-internet-security-including-cav-and-firewall/

Related Comodo vulnerability background:

- NVD CVE-2025-7098, Comodo Internet Security path traversal: https://nvd.nist.gov/vuln/detail/CVE-2025-7098
- Heise coverage of 2025 Comodo Internet Security update-chain issues: https://www.heise.de/en/news/Antivirus-Comodo-Internet-Security-allows-malicious-code-to-be-planted-10477015.html
- NVD CVE-2024-7251, Comodo Internet Security Pro `cmdagent` link-following LPE: https://nvd.nist.gov/vuln/detail/CVE-2024-7251

## Study Questions

1. Which Windows filtering layer receives the packet before a third-party firewall driver sees it?
2. Does the component implement WFP callouts, an NDIS filter, a legacy path, or a product-specific combination?
3. What object carries packet buffers at the layer under study: `NET_BUFFER_LIST`, stream data, or higher-level metadata?
4. What parser assumptions are risky for IPv6 extension headers, fragmentation, and header-data split?
5. What would a crash dump need to prove before attributing fault to `Inspect.sys` instead of `tcpip.sys`, NDIS, or another filter?
6. Which telemetry can show the product version, loaded driver, service name, and crash bucket without reproducing the bug?
7. What would distinguish remotely reachable kernel DoS from remotely reachable code execution?
8. What vendor data is still missing: CVE, affected versions, fixed versions, patch date, and workaround?

## Defensive Takeaway

Security products that parse network input in kernel mode create privileged remote attack surface. The safer design question is not only whether a firewall driver blocks more packets, but whether the same policy can be expressed through supported WFP rules while minimizing custom packet parsing in kernel mode.

For this repo, the future deep-dive target is:

```text
product driver inventory
  -> network layer and callback/callout map
  -> input object model
  -> parser invariant
  -> crash evidence
  -> vendor advisory and fixed-build tracking
```

Do not integrate packet bytes, exploit trigger logic, or PoC reconstruction into first-party docs.

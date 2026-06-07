# References — Network Blocking EDR Evasion

## Primary Sources

### EDRChoker
- Blog: https://www.zerosalarium.com/2026/06/edrchoker-choking-telemetry-stream-block-edr.html
- Technique: QoS / pacer.sys bandwidth throttling to silence EDR telemetry

### 360WFP_Exploit
- GitHub: https://github.com/kyxiaxiang/360WFP_Exploit
- Technique: BYOVD — abuse 360 Security's WFP driver IOCTL to block any process

### EDRPrison
- GitHub: https://github.com/senzee1984/EDRPrison
- Blog: https://www.3nailsinfosec.com/post/edrprison-borrow-a-legitimate-driver-to-mute-edr-agent
- Technique: BYOVD — WinDivert-based packet-level EDR blocking

---

## Research Articles

### WFP Manipulation
- SCRT Team Blog — *Blinding EDRs: A deep dive into WFP manipulation* (2025):
  https://blog.scrt.ch/2025/08/25/blinding-edrs-a-deep-dive-into-wfp-manipulation/

- WFP Wizardry — *Abusing WFP for EDR Evasion* (2025):
  https://jacobkalat.com/edr-evasion/2025/02/12/WFP-Wizardry-Abusing-WFP-for-EDR-Evasion.html

- HackMag — *EDR Jammer: Bypassing security mechanisms through WFP*:
  https://hackmag.com/security/wfp-bypass

- Undercode Testing — *How to Block EDR Traffic Using Windows Firewall and WFP*:
  https://undercodetesting.com/bypassing-edr-how-to-block-edr-traffic-using-windows-firewall-and-wfp/

### WFP Internals / Reverse Engineering
- 0mWindyBug — *Windows Filtering Platform internals: Reverse Engineering the callout mechanism*:
  https://0mwindybug.github.io/WFP/

- WFP Callout Research repository:
  https://github.com/0mWindyBug/WFPCalloutReserach

- Quarkslab — *Guided tour inside WinDefender's network inspection driver*:
  https://blog.quarkslab.com/guided-tour-inside-windefenders-network-inspection-driver.html

### EDR Silencing (General)
- Vectra — *EDR evasion: techniques, real-world breaches, and defenses*:
  https://www.vectra.ai/topics/edr-evasion

- PacketLabs — *How EDRSilencer Helps Attackers Bypass EDR Security Solutions*:
  https://www.packetlabs.net/posts/how-edrsilencer-helps-attackers-bypass-edr-security-solutions/

- SecurityHQ — *What is an EDR Silencer?*:
  https://www.securityhq.com/blog/what-is-an-endpoint-detection-response-edr-silencer/

### BYOVD
- Infiltr8 Red Book — *Bring Your Own Vulnerable Driver (BYOVD)*:
  https://red.infiltr8.io/redteam/evasion/endpoint-detection-respons-edr-bypass/bring-your-own-vulnerable-driver-byovd

- Deep Instinct — *NoFilter: Abusing WFP for Privilege Escalation*:
  https://www.deepinstinct.com/blog/nofilter-abusing-windows-filtering-platform-for-privilege-escalation

---

## Tools Referenced

| Tool | Purpose | URL |
|---|---|---|
| EDRSilencer | WFP filter injection | https://github.com/netero1010/EDRSilencer |
| EDRPrison | WinDivert packet blocking | https://github.com/senzee1984/EDRPrison |
| WFPExplorer | WFP GUI inspector | https://github.com/zodiacon/WFPExplorer |
| WinDivert | Packet interception driver | https://reqrypt.org/windivert.html |
| 360WFP_Exploit | 360 driver BYOVD PoC | https://github.com/kyxiaxiang/360WFP_Exploit |

---

## Microsoft Documentation

- WFP Overview: https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page
- WFP Callout Drivers: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/introduction-to-windows-filtering-platform-callout-drivers
- WFP Filter Conditions: https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions
- QoS Policy: https://learn.microsoft.com/en-us/windows-server/networking/technologies/qos/qos-policy-top
- WDAC: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/wdac

---

## Related Modules in This Repository

- `../01_core-handbook/` — Windows kernel fundamentals
- `../02_mitigations-vbs-hvci-vtrp/` — HVCI and VBS mitigations (blocks unsigned callout drivers)
- `../03_byovd/` — BYOVD technique details (driver loading, DSE bypass)
- `../docs/360-driver-ida-reverse-notes.md` — IDA reverse engineering notes for 360 driver

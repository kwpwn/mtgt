# 07 — Cobalt Strike Complete Command Reference

Comprehensive bilingual (English + Vietnamese) reference for Cobalt Strike 4.x.

---

## Documents

### Core Command Reference

| File | Language | Description |
|---|---|---|
| [cobalt-strike-complete-reference-EN.md](cobalt-strike-complete-reference-EN.md) | English | All Beacon commands, Aggressor Script, advanced chaining |
| [cobalt-strike-complete-reference-VI.md](cobalt-strike-complete-reference-VI.md) | Vietnamese | Same — full bilingual translation |

### Malleable C2 Profile

| File | Language |
|---|---|
| [cobalt-strike-malleable-c2-EN.md](cobalt-strike-malleable-c2-EN.md) | English |
| [cobalt-strike-malleable-c2-VI.md](cobalt-strike-malleable-c2-VI.md) | Vietnamese |

Deep dive: profile syntax, http-get/post/stager blocks, dns-beacon, stage block (sleep_mask, stomppe, module stomping), post-ex block, process-inject block, complete profile examples (Amazon S3, jQuery CDN, Office 365).

### Persistence Techniques

| File | Language |
|---|---|
| [cobalt-strike-persistence-EN.md](cobalt-strike-persistence-EN.md) | English |
| [cobalt-strike-persistence-VI.md](cobalt-strike-persistence-VI.md) | Vietnamese |

Covers: registry Run keys, scheduled tasks (XML), services, startup folder, WMI event subscriptions, COM hijacking, DLL hijacking, Office add-ins, boot-level persistence, LSASS SSP, domain-level persistence (AdminSDHolder, GPO logon scripts).

### OPSEC Guide

| File | Language |
|---|---|
| [cobalt-strike-opsec-guide-EN.md](cobalt-strike-opsec-guide-EN.md) | English |
| [cobalt-strike-opsec-guide-VI.md](cobalt-strike-opsec-guide-VI.md) | Vietnamese |

Covers: team server hardening, sleep/jitter strategy, process injection OPSEC, network traffic OPSEC (domain selection, redirectors, CDN fronting), memory OPSEC (sleep mask, stack spoofing, module stomping), credential OPSEC, lateral movement risk matrix, file/disk OPSEC, detection signatures, common mistakes, full OPSEC checklist.

### Active Directory Enumeration

| File | Language |
|---|---|
| [cobalt-strike-ad-enumeration-EN.md](cobalt-strike-ad-enumeration-EN.md) | English |
| [cobalt-strike-ad-enumeration-VI.md](cobalt-strike-ad-enumeration-VI.md) | Vietnamese |

Covers: domain/forest/DC recon, user/group/computer enumeration, GPO/OU, trust enumeration, ACL analysis (GenericAll, WriteDACL, DCSync rights), SPN/Kerberoasting, BloodHound data collection, complete PowerView function reference, ADCS enumeration (ESC1–ESC8), LDAP direct queries, Situational Awareness BOFs, attack path decision tree.

### BOF Development

| File | Language |
|---|---|
| [cobalt-strike-bof-development-EN.md](cobalt-strike-bof-development-EN.md) | English |
| [cobalt-strike-bof-development-VI.md](cobalt-strike-bof-development-VI.md) | Vietnamese |

Covers: BOF architecture, COFF constraints, development environment (MinGW/VS/Zig), beacon.h API reference, dynamic API resolution pattern, BeaconDataParser argument handling, output functions, complete BOF examples (process lister, registry query, token manipulation, network check), Aggressor Script integration, compile commands, local testing with COFFLoader.

### Initial Access & Phishing

| File | Language |
|---|---|
| [cobalt-strike-initial-access-EN.md](cobalt-strike-initial-access-EN.md) | English |
| [cobalt-strike-initial-access-VI.md](cobalt-strike-initial-access-VI.md) | Vietnamese |

Covers: CS spear phishing module, Office macro payloads, MOTW bypass strategies, HTA delivery, ISO/LNK delivery, scripted web delivery (PowerShell/regsvr32/bitsadmin/mshta), web drive-by (clone site, credential harvesting), CHM/PDF weaponized attachments, payload hosting, anti-sandbox techniques, USB/Rubber Ducky, phishing OPSEC (domain categorization, DKIM/SPF/DMARC, timing).

### Troubleshooting

| File | Language |
|---|---|
| [cobalt-strike-troubleshooting-EN.md](cobalt-strike-troubleshooting-EN.md) | English |
| [cobalt-strike-troubleshooting-VI.md](cobalt-strike-troubleshooting-VI.md) | Vietnamese |

Covers: Beacon not connecting (diagnosing connectivity, TLS, redirectors), Beacon dying (AV/EDR in-memory detection, arch mismatch), commands not returning output (fork&run killed, AMSI), injection/execute-assembly failures, privilege escalation failures, lateral movement failures, DNS/SMB/TCP Beacon issues, team server startup/memory issues, Malleable C2 profile issues, AV/EDR bypass, error message table, diagnostic commands.

---

## Coverage Summary

| Topic | EN | VI |
|---|---|---|
| All Beacon commands (100+) | ✓ | ✓ |
| Aggressor Script (b* functions, events, dialogs, menus) | ✓ | ✓ |
| Malleable C2 profile deep dive | ✓ | ✓ |
| Persistence (8 mechanism categories) | ✓ | ✓ |
| OPSEC guide + checklist | ✓ | ✓ |
| AD enumeration + BloodHound + PowerView | ✓ | ✓ |
| BOF development (write, compile, load, test) | ✓ | ✓ |
| Initial access + phishing | ✓ | ✓ |
| Troubleshooting | ✓ | ✓ |
| Quick reference cheat sheet | ✓ | ✓ |

Total: ~16 documents, ~700+ KB of reference material.

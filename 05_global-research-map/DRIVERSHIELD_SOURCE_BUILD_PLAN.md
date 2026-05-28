# DriverShield Source Build Plan

Updated: 2026-05-27

## Purpose

DriverShield is useful for this repository because it is not just one blog post.
It is a driver-intelligence hub with:

- a driver database,
- a CVE library,
- a signer atlas,
- a BYOVD research index,
- a documented analysis methodology,
- a hash lookup API.

This document turns DriverShield into a repeatable source-mining workflow for
building our own Windows kernel driver research material.

Important boundary:

```text
Use DriverShield as a source index and metadata pivot.
Do not copy its reports wholesale.
Do not treat its verdict as proof.
Verify every claim against vendor advisories, MSRC/NVD, LOLDrivers, symbols,
local reversing, and lab behavior.
```

## Source Pages

Primary DriverShield pages:

- Home: https://drivershield.io/
- Driver database: https://drivershield.io/database/
- CVE library: https://drivershield.io/cves/
- Signer atlas: https://drivershield.io/signers/
- BYOVD research index: https://drivershield.io/byovd/
- Methodology: https://drivershield.io/methodology/
- API documentation: https://drivershield.io/api/
- Glossary: https://drivershield.io/glossary/
- Sitemap: https://drivershield.io/sitemap.xml

Related external pivots:

- LOLDrivers: https://www.loldrivers.io/
- Microsoft vulnerable driver block rules:
  https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules
- NVD: https://nvd.nist.gov/
- MSRC: https://msrc.microsoft.com/update-guide/

## Why DriverShield Is Valuable

### 1. It gives broad coverage

The sitemap exposes many per-driver report URLs. That makes it useful for
building a queue of driver samples to classify by:

```text
driver
  -> hash
  -> scan id
  -> signer
  -> verdict/risk
  -> CVE relation
  -> ATT&CK mapping
  -> dangerous API/IOCTL surface
```

### 2. It gives a methodology we can mirror

DriverShield documents a 14-stage static pipeline:

```text
hashing
PE validation
section entropy
version resources
import scan
IOCTL extraction
Authenticode parsing
mitigation checks
YARA matching
known-vulnerable cross-reference
multi-engine consensus
symbolic execution
string classification
ATT&CK/Sigma/risk score
```

For this repository, we should convert that into our own review checklist,
not blindly reuse their score.

### 3. It has useful pivots

Driver research works best when pivoting from multiple dimensions:

| Pivot | Research value |
|---|---|
| SHA256 | exact sample identity, dedup, reproducibility |
| filename | weak but useful first clue |
| signer | vendor/certificate clustering |
| CVE | public advisory and patch path |
| YARA hits | known family or vulnerable-driver signature |
| MITRE IDs | behavior class, not exploitability proof |
| risk score | triage priority, not final truth |
| verdict | prioritization only |

## DriverShield Data Model For Our Repo

Every harvested DriverShield item should become this local record:

```text
driver_name:
sha256:
drivershield_url:
drivershield_scan_id:
drivershield_verdict:
drivershield_risk_score:
signer:
vendor:
cve_ids:
lol_drivers_link:
microsoft_blocklist_status:
known_public_writeups:
primitive_class:
reachability_notes:
loadability_notes:
mitigation_notes:
research_priority:
local_doc_target:
verification_status:
```

Do not mark `primitive_class` as final until local/manual verification supports
it.

## API Usage Model

DriverShield documents a public hash lookup endpoint:

```text
GET /?r=apilookup&sha256={64-char-hex-hash}
```

Documented response fields include:

```text
found
sha256
filename
risk_score
verdict
vt_detections
vt_total
yara_matches
scanned_at
mitre
```

Use this API for metadata enrichment only. It does not replace reversing.

### Local Lookup Record

For each hash lookup, save the result conceptually as:

```text
source: DriverShield API
retrieved_at: YYYY-MM-DD
hash: SHA256
found: true/false
risk_score:
verdict:
mitre:
notes:
```

Do not upload proprietary, customer, or third-party driver samples unless you
have permission and understand the platform's terms.

## Harvest Workflow

### Step 1. Pull site structure

Use the sitemap as the discovery entry:

```text
DriverShield sitemap
  -> top-level pages
  -> per-driver report URLs
  -> scan ids and hashes
```

Goal:

```text
build a queue, not a conclusion
```

### Step 2. Deduplicate by hash

Two names can point to the same binary. Two binaries can share a filename.

Local rule:

```text
sha256 is identity
filename is only a clue
```

### Step 3. Enrich each hash

For each hash:

```text
DriverShield API
  -> filename/risk/verdict/MITRE/YARA
LOLDrivers
  -> vulnerable-driver family status
MSRC/NVD/vendor
  -> CVE and fixed version
Microsoft blocklist
  -> loadability under policy
local reversing
  -> primitive and reachability
```

### Step 4. Classify primitive

Use this local primitive taxonomy:

| DriverShield clue | Local classification question |
|---|---|
| IOCTL extraction | Is there a reachable user/kernel control path? |
| dangerous imports | Does import usage imply physical, MSR, port, MMIO, callback, process, file, registry, or copy primitive? |
| YARA vulnerable-driver match | Which public driver family does it map to? |
| CVE relation | Is the CVE about loadability, access control, memory corruption, or privileged operation exposure? |
| signer cluster | Is the signer associated with many vulnerable samples? |
| MITRE IDs | What behavior class is suggested, and is it relevant to kernel exploitability? |

### Step 5. Create local case notes

Each high-value entry becomes one of:

```text
03_byovd/00_index-and-matrix/BYOVD_CASE_<DRIVER>.md
03_byovd/<primitive-folder>/<DRIVER>_DEEP_DIVE.md
docs/kernel-research/<technique>-research-notes.md
docs/research-index/<source>-triage.md
```

Do not create a case-study doc until at least one of these is true:

- there is a vendor/MSRC/NVD advisory,
- LOLDrivers maps the sample/family,
- a public technical writeup exists,
- local reversing confirms a meaningful primitive,
- the signer/family is high-value enough for source intelligence.

## Research Queue Fields

Use this triage table when importing candidates:

| Field | Meaning |
|---|---|
| Priority | `P1`, `P2`, `P3`, or `Backlog` |
| Driver | filename/family |
| Hash | SHA256 |
| Source | DriverShield URL/API, LOLDrivers, vendor, blog |
| Primitive guess | physical, virtual R/W, MSR, port, MMIO, callback, file/registry/filter, process semantic action, unknown |
| Confidence | low/medium/high |
| Why interesting | one sentence |
| Next verification | exact research step |
| Output doc | target markdown file |

## Initial DriverShield-Driven Workstreams

### Workstream A: Known CVE Drivers

Source:

```text
DriverShield CVE library
```

Observed CVE seed examples from the page:

- CVE-2013-3956
- CVE-2017-9769
- CVE-2022-26522
- CVE-2022-26523
- CVE-2023-1453
- CVE-2024-41498
- CVE-2024-26229
- CVE-2022-42046
- CVE-2022-3699
- CVE-2023-52271
- CVE-2019-18845
- CVE-2024-26506
- CVE-2018-16712
- CVE-2018-5713
- CVE-2009-0824
- CVE-2024-22830
- CVE-2007-5633
- CVE-2023-21768
- CVE-2020-17382
- CVE-2015-2291

How to use:

```text
CVE
  -> affected driver family
  -> vendor advisory
  -> LOLDrivers mapping
  -> primitive class
  -> loadability status
  -> local case note
```

### Workstream B: Signer Clustering

Source:

```text
DriverShield signer atlas
```

Use signer clusters to answer:

```text
which vendors/signers appear repeatedly?
which signers are timestamp-only versus actual code signers?
which samples are legitimate platform drivers versus suspicious test-signed or
compromised-signing cases?
```

Do not overinterpret signer alone. A signer pivot is a clustering tool, not a
vulnerability proof.

### Workstream C: BYOVD GitHub Index

Source:

```text
DriverShield BYOVD Research Index
```

Use it to find upstream repositories, then apply this repo's public-PoC reading
template:

```text
repo
  -> driver family
  -> exploit primitive claimed
  -> public code present?
  -> exact affected version?
  -> mitigation assumptions?
  -> what not to copy?
  -> local teaching note
```

### Workstream D: High-Risk API Import Clusters

Source:

```text
DriverShield methodology: dangerous kernel API enumeration
```

Group samples by suspicious import family:

| Import family | Possible primitive |
|---|---|
| physical mapping APIs | physical memory read/write |
| MSR intrinsics | MSR read/write |
| port I/O intrinsics | port I/O |
| PCI/MMIO APIs | hardware/MMIO primitive |
| process/thread APIs | process semantic actions |
| callback registration/unregistration | visibility/security-state tamper |
| memory copy/probe APIs | virtual kernel R/W or METHOD_NEITHER bug class |

This is only a starting hypothesis. Imports do not prove reachability.

## Local Output Templates

### Per-Driver Case Study

```text
# BYOVD Case Study: <driver>

Sources:
- DriverShield:
- LOLDrivers:
- Vendor/MSRC/NVD:
- Public writeups:

Identity:
- filename:
- sha256:
- signer:
- version:

Primitive:
- claimed:
- verified:
- confidence:

Reachability:
- device object:
- ACL:
- required hardware/software:
- user privilege:

Bridge:
- kernel base discovery:
- object discovery:
- primitive upgrade:
- objective:

Mitigation pressure:
- Microsoft blocklist:
- WDAC:
- HVCI:
- PatchGuard:
- build sensitivity:

Failure modes:
- ...

Study questions:
- ...
```

### Source Triage Entry

```text
## <driver/hash>

DriverShield:
Other sources:
Priority:
Primitive guess:
Confidence:
Why interesting:
Next verification:
Output target:
```

## Quality Rules

1. DriverShield risk score is triage, not truth.
2. DriverShield verdict is a starting point, not a final label.
3. Hash identity matters more than filename.
4. CVE pages need vendor/MSRC/NVD confirmation.
5. Signer pivots need actual signer-chain interpretation.
6. Dangerous imports need reachability analysis.
7. IOCTL extraction needs access-control and transfer-method analysis.
8. Do not copy exploit code from upstream repositories.
9. Do not add runnable trigger buffers to this repo.
10. Keep primitive, bridge, and objective separate.

## Immediate Repo Tasks

Priority additions from this source strategy:

1. Read `03_byovd/00_index-and-matrix/BYOVD_DRIVERSHIELD_BLOG_TECHNIQUE_ATLAS.md`
   for the first pass of technique extraction from DriverShield-indexed
   writeups.
2. Build a `DRIVERSHIELD_TRIAGE_QUEUE.md` from selected high-risk DriverShield
   database entries.
3. Add per-driver notes for CVE drivers not already covered by this repo.
4. Cross-reference DriverShield hashes against LOLDrivers names.
5. Add a signer-pivot note for repeated vendor/signer clusters.
6. Add a local methodology checklist mirroring the 14-stage analysis pipeline.

## References

- DriverShield home: https://drivershield.io/
- DriverShield database: https://drivershield.io/database/
- DriverShield CVE library: https://drivershield.io/cves/
- DriverShield signer atlas: https://drivershield.io/signers/
- DriverShield BYOVD research index: https://drivershield.io/byovd/
- DriverShield methodology: https://drivershield.io/methodology/
- DriverShield API: https://drivershield.io/api/
- DriverShield glossary: https://drivershield.io/glossary/
- Local DriverShield technique atlas:
  `03_byovd/00_index-and-matrix/BYOVD_DRIVERSHIELD_BLOG_TECHNIQUE_ATLAS.md`

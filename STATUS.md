# Full Chain Exploits — Chrome 146.0.7680.165 Comprehensive Audit

## Target
- **Chrome**: 146.0.7680.165 / V8 14.6.202.26
- **OS**: Windows 11 Build 26200.8875 (25H2)
- **Goal**: TRUE real-world RCE + sandbox escape, NO admin, NO orchestrator cheating

---

## Chain 1 (Original): CVE-2026-6307 + CVE-2026-40369
- **Entry**: TurboFan FrameState CSE addrof/fakeobj
- **V8 SBX bypass**: Orchestrator WPM (CHEATING)
- **Sandbox escape**: CVE-2026-40369 kernel (CmpLayerVersionCount)
- **Status**: CONFIRMED WORKING (V8 SBX step cheats)
- **File**: orchestrator.py

## Chain 2: crbug-542403045 + CVE-2026-6307 + CVE-2026-40369
- **Entry**: Sort element kind confusion addrof + FrameState CSE fakeobj
- **V8 SBX bypass**: Orchestrator WPM (CHEATING)
- **Sandbox escape**: CVE-2026-40369 kernel
- **Status**: Code written, NEEDS TESTING
- **File**: orchestrator_sort.py

## Chain A (NEW): CVE-2026-6307 + WCPT UAF + CVE-2026-40369
**Orchestrator-assisted chain with WCPT V8 SBX bypass**
- **Entry**: CVE-2026-6307 FrameState CSE in-cage arb R/W
- **V8 SBX bypass**: WCPT UAF (issues 446113730/452605803)
- **Sandbox escape**: CVE-2026-40369 kernel
- **Status**: Code written, SUPERSEDED by Real-World chain
- **File**: orchestrator_chain_a.py

## Real-World Chain (BEST): CVE-2026-6307 + CVE-2026-5281
**2-STAGE — NO kernel, NO admin, NO WCPT, NO separate V8 SBX bypass**
- **Stage 1**: CVE-2026-6307 = BOTH RCE AND V8 sandbox bypass
  - Full 64-bit fakeobj bypasses EPT/CPT/TPT directly
  - JIT code staging + property store → native code execution
  - No WCPT/EPT corruption needed (Nebula Security technique)
- **Stage 2**: CVE-2026-5281 Dawn WebGPU buffer UAF
  - Bind groups retain stale refs (bypasses CVE-2026-4676 fix)
  - buffer.destroy() race with GPU execution → UAF in GPU process
  - CVSS 8.8, CISA KEV, ITW 0-day
  - Fixed in 146.0.7680.178 (our .165 IS VULNERABLE)
- **Advantage**: Cross-platform, no kernel deps, simplified 2-stage chain
- **Status**: Code written, NEEDS TESTING
- **File**: orchestrator_realworld.py, dawn_escape.js

---

## Vulnerability Catalog (Chrome 146.0.7680.165)

### V8 RCE
| CVE | Description | Range | Status |
|-----|-------------|-------|--------|
| CVE-2026-6307 | FrameState CSE | 106-147 | EXPLOIT WRITTEN |
| crbug-542403045 | Sort kind confusion | <=151 | EXPLOIT WRITTEN |
| CVE-2026-5873 | Turboshaft WASM OOB | 138-146 | CODE WRITTEN |
| CVE-2026-85046 | Maglev PACKED confusion | <152 | NO POC |

### V8 Sandbox Bypass
| Issue | Description | Range | Status |
|-------|-------------|-------|--------|
| 446113730 | WCPT UAF dispatch table | ~138-146 | CODE WRITTEN |
| 452605803 | WCPT UAF variant | ~138-146 | CODE WRITTEN |
| 352689356-421403261 | Petitoto techniques | <=137 | PATCHED |

### Chrome Sandbox Escape
| CVE | Description | Type | Range | Status |
|-----|-------------|------|-------|--------|
| CVE-2026-40369 | CmpLayerVersionCount | Kernel | Win11 | EXPLOIT WRITTEN |
| CVE-2026-5281 | Dawn buffer UAF | GPU proc | <.178 | CODE WRITTEN |
| CVE-2026-6310 | Dawn UAF | GPU proc | <147 | RESEARCH |
| CVE-2026-8580 | Mojo IPC UAF | Browser | <148.0.7778.168 | CODE WRITTEN |
| CVE-2026-8523 | Mojo IPC UAF #2 | Browser | <148 | RESEARCH |

### NOT viable
- CVE-2026-4676: Fixed in exactly 146.0.7680.165
- CVE-2025-2783: Fixed in Chrome 134
- CVE-2024-11114: Fixed much earlier

---

## Key Findings

1. CVE-2026-6307 IS BOTH RCE AND V8 sandbox bypass (full 64-bit fakeobj bypasses EPT/CPT/TPT)
2. No separate V8 SBX bypass needed — WCPT technique SUPERSEDED
3. JIT code staging + property store = native code exec from single bug
4. CVE-2026-5281 Dawn UAF: real sandbox escape, target IS vulnerable (bug 491518608)
5. CVE-2026-5281 bypasses CVE-2026-4676 fix via bind group stale references
6. CVE-2026-8580 Mojo UAF: CVSS 9.6, bug 496639647, Scope:Changed → browser process escape
7. Mojo chain advantage: no GPU dependency, more deterministic than Dawn

## Files
| File | Purpose |
|------|---------|
| **orchestrator_realworld.py** | **Real-World chain (BEST): CVE-2026-6307 + CVE-2026-5281** |
| **dawn_escape.js** | **Dawn WebGPU UAF standalone trigger** |
| **exploit_realworld.html** | **Real-World chain description** |
| orchestrator.py | Chain 1 (original, orchestrator-assisted) |
| orchestrator_sort.py | Chain 2 (sort confusion) |
| orchestrator_chain_a.py | Chain A (WCPT UAF, superseded) |
| orchestrator_mojo.py | Mojo IPC chain: CVE-2026-6307 + CVE-2026-8580 |
| orchestrator_dawn.py | Chain D (Dawn WebGPU, older version) |
| exploit.html | Chain 1 reference |
| exploit_sort.html | Chain 2 reference |
| exploit_chain_a.html | Chain A reference |
| crbug-542403045-analysis.md | Sort confusion analysis |
| CHAIN_AUDIT.md | Comprehensive vulnerability audit |
| find_cmplayer.py | CmpLayerVersionCount RVA finder |
| diag_win10.py | CVE-2026-40369 diagnostic |
| WRITEUP.md | Technical writeup |

## CLI
```
python orchestrator_chain_a.py --chrome <path> --stage2 <stage2.bin>
python orchestrator_chain_a.py --chain-b --chrome <path> --stage2 <stage2.bin>
python orchestrator_dawn.py --chrome <path>
python orchestrator.py --chrome <path> --stage2 <stage2.bin>
python orchestrator_sort.py --chrome <path> --stage2 <stage2.bin>
```

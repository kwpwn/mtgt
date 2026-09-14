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
**BEST CHAIN — TRUE real-world sandbox escape**
- **Entry**: CVE-2026-6307 FrameState CSE in-cage arb R/W
- **V8 SBX bypass**: WCPT UAF (issues 446113730/452605803)
  - WasmTableObject dispatch_table handle corruption
  - CanonicalSig confusion: ref to i64 reinterpretation
  - PKU not enforced on Windows Chrome 146
- **Sandbox escape**: CVE-2026-40369 kernel
- **Status**: Code written, NEEDS TESTING
- **File**: orchestrator_chain_a.py
- **Also**: --chain-b uses CVE-2026-5873 Turboshaft WASM OOB as RCE

## Chain D (NEW): CVE-2026-6307 + CVE-2026-5281 (Dawn WebGPU)
**NO KERNEL EXPLOIT NEEDED**
- **Entry**: CVE-2026-6307 FrameState CSE V8 RCE
- **Sandbox escape**: CVE-2026-5281 Dawn WebGPU buffer UAF
  - buffer.destroy() after queue.submit() frees VRAM while GPU uses it
  - CVSS 8.8, CISA KEV, ITW 0-day
  - Fixed in 146.0.7680.178 (our .165 IS VULNERABLE)
- **Advantage**: Works on any Windows, no kernel RVA deps
- **Status**: Code written, NEEDS TESTING
- **File**: orchestrator_dawn.py

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
| CVE-2026-8580 | Mojo IPC UAF | Browser | <148 | RESEARCH |
| CVE-2026-8523 | Mojo IPC UAF #2 | Browser | <148 | RESEARCH |

### NOT viable
- CVE-2026-4676: Fixed in exactly 146.0.7680.165
- CVE-2025-2783: Fixed in Chrome 134
- CVE-2024-11114: Fixed much earlier

---

## Key Findings

1. CVE-2026-6307 IS full V8 sandbox bypass on Windows (PKU not enforced)
2. WCPT UAF provides clean V8 SBX bypass for Chrome 138-146
3. CVE-2026-5281 Dawn UAF: real sandbox escape, target IS vulnerable
4. CVE-2026-8580 Mojo UAF: CVSS 9.6, fixed in Chrome 148 (needs diff)

## Files
| File | Purpose |
|------|---------|
| orchestrator.py | Chain 1 (original) |
| orchestrator_sort.py | Chain 2 (sort confusion) |
| orchestrator_chain_a.py | Chain A (TRUE escape, WCPT UAF) |
| orchestrator_dawn.py | Chain D (Dawn WebGPU, no kernel) |
| exploit.html | Chain 1 reference |
| exploit_sort.html | Chain 2 reference |
| exploit_chain_a.html | Chain A reference |
| crbug-542403045-analysis.md | Sort confusion analysis |
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

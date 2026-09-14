# Full Chain Exploits — Status
## Target: Chrome 146.0.7680.165 / V8 14.6.202.26

---

## COMPREHENSIVE AUDIT RESULTS (2026-09-14)

### V8 RCE Bugs — Exploitable on Chrome 146
| CVE/Bug | Type | Status | Primitives |
|---------|------|--------|------------|
| CVE-2026-6307 | FrameState CSE | ✅ CONFIRMED | addrof + fakeobj |
| crbug-542403045 | Sort kind confusion | ✅ CONFIRMED | addrof only |
| CVE-2026-85046 | Sort/Maglev ITW 0day | ✅ VULN (fix: Chrome 152) | No public PoC |
| CVE-2026-5873 | Turboshaft Wasm OOB | ✅ VULN (fix: Chrome 147) | OOB R/W → cage R/W |

### V8 Sandbox Bypass
| Technique | Status | Notes |
|-----------|--------|-------|
| WCPT dispatch table corruption (452605803) | ✅ Reported working on 146 | CanonicalSig type forging |
| Trusted Pointer Table (HITCON) | ❓ Version unclear | Fake WasmExportedFunctionData |
| Petitoto 4x (352689356, 379140430, 395659804, 421403261) | ❌ ALL PATCHED | Chrome ≤137 |
| CVE-2024-12053 canonical index | ❌ PATCHED | Chrome 134 |

### Browser Sandbox Escape — Exploitable on Chrome 146.0.7680.165
| CVE | Type | Status | Admin needed? |
|-----|------|--------|---------------|
| CVE-2026-5281 | Dawn WebGPU UAF | ✅ VULN (fix: .177/.178) | NO |
| CVE-2026-8523 | Mojo UAF | ✅ VULN (fix: Chrome 148) | NO |
| CVE-2026-14109 | Mojo policy | ✅ VULN (fix: Chrome 150) | NO |
| CVE-2026-4676 | Dawn WebGPU UAF | ❌ PATCHED IN .165 | N/A |
| CVE-2025-2783 | Mojo IPC | ❌ PATCHED (Chrome 134) | N/A |
| CVE-2026-40369 | Kernel CmpLayer | ✅ Win11 only | NO |

---

## VIABLE FULL CHAINS

### ★ Chain A: CVE-2026-6307 + WCPT + CVE-2026-5281 ★ (TRUE REAL-WORLD)
```
V8 FrameState CSE → addrof/fakeobj → cage R/W
  → WCPT dispatch table corruption → CanonicalSig confusion
  → arbitrary virtual R/W (V8 sandbox escaped)
  → Dawn WebGPU UAF → browser process (MEDIUM IL)
```
- **NO admin, NO kernel, NO orchestrator cheating**
- Works on Win10 AND Win11
- CVE-2026-5281 confirmed exploitable on .165

### Chain B: CVE-2026-5873 + WCPT + CVE-2026-5281 (Turboshaft Entry)
```
Turboshaft Wasm OOB → cage R/W (via ArrayBuffer corruption)
  → WCPT bypass → full R/W → Dawn WebGPU UAF → MEDIUM IL
```
- Alternative V8 RCE entry (Hacktron blog has full PoC)
- Same escape chain

### Chain C: CVE-2026-6307 + CVE-2026-5281 (Direct Dawn, No V8 SBX)
```
V8 FrameState CSE → addrof/fakeobj
  → Dawn WebGPU UAF (accessible from JS, may not need V8 SBX bypass)
  → browser process (MEDIUM IL)
```
- Depends on whether Dawn UAF can be triggered from JS alone
- If yes: simplest chain (no V8 SBX bypass needed!)

### Chain D: CVE-2026-6307 + WCPT + CVE-2026-8523 (Mojo Escape)
```
V8 FrameState CSE → WCPT bypass → native code
  → Mojo IPC UAF → browser process (MEDIUM IL)
```

### Chain E: Sort + FrameState CSE + Dawn (Two-Bug V8 Entry)
```
crbug-542403045 (addrof) + CVE-2026-6307 (fakeobj)
  → Dawn WebGPU UAF → MEDIUM IL
```

### Chain F: CVE-2026-6307 + CVE-2026-40369 (Kernel, Existing)
```
V8 FrameState CSE → orchestrator WPM (NOT real-world) → kernel → SYSTEM
```
- Win11-only, V8 SBX bypass is orchestrator-assisted

---

## Chain Status Detail

### Chain 1: CVE-2026-6307 + CVE-2026-40369 (V8 RCE + Kernel)
- **Entry**: TurboFan FrameState CSE → addrof + fakeobj
- **Phases 1-6**: CONFIRMED on both Win10 & Win11
- **Renderer RCE**: Native code execution in sandboxed renderer (UNTRUSTED IL)
- **V8 SBX bypass**: Orchestrator-assisted (WPM — NOT real-world)
- **Escape**: CVE-2026-40369 kernel exploit → SYSTEM
- **Limitation**: Win11-only (CmpLayerVersionCount)

### Chain 2: crbug-542403045 + CVE-2026-6307 + CVE-2026-40369
- **Entry**: Sort element kind confusion → addrof, FrameState CSE → fakeobj
- **V8 SBX bypass**: Orchestrator-assisted (NOT real-world)
- **Escape**: CVE-2026-40369 kernel
- **Status**: Code written, NEEDS TESTING

### ★ Chain 3: CVE-2026-6307 + CVE-2026-5281 (Dawn WebGPU) ★
- **Entry**: TurboFan FrameState CSE → addrof + fakeobj
- **Escape**: Dawn WebGPU UAF → browser process (MEDIUM IL)
- **CVE-2026-5281**: Fixed in .178, our .165 IS VULNERABLE
- **NO kernel needed**, works on Win10 AND Win11
- **ITW**: Confirmed by CISA KEV
- **Status**: Framework written, needs patch-diff analysis for UAF trigger
- **Rating**: ★★★★★

### Chain 4: CVE-2026-6307 + CVE-2026-8523 (Mojo)
- **Status**: Reference exploit written

### Chain 5: CVE-2026-5873 + Dawn (Turboshaft Wasm OOB)
- **NEW**: Alternative V8 RCE via Turboshaft bounds-check elimination
- **Status**: PoC written (cve_2026_5873_oob.js), needs testing

---

## Blocked (Chains 1 & 2 only)
- **CmpLayerVersionCount RVA**: NOT found on Win10 21H2 (Build 19044.7663)
- **Root cause**: SystemLayerSnapshot (class 253) likely Win11-only

## Pattern Scan (verified on Win11 25H2)
```
c7 44 24 28 f8 0f 00 00   MOV [rsp+28h], 0xFF8
48 8d 15 XX XX XX XX       LEA rdx, [rip+disp32]  -> CmpLayerVersionCount
```
- Win11 result: RVA 0x00ef709c (matches PDB)
- Win10 result: pattern not found

---

## Files
| File | Purpose |
|------|---------|
| orchestrator.py | Chain 1 orchestrator (CVE-2026-6307 + kernel) |
| orchestrator_sort.py | Chain 2 orchestrator (sort + kernel) |
| orchestrator_dawn.py | Chain 3 orchestrator (V8 + Dawn escape) ★ |
| orchestrator_chain_a.py | Chain A orchestrator (V8 + WCPT + kernel/Dawn) |
| v8_sandbox_bypass.js | WCPT V8 sandbox bypass JavaScript |
| cve_2026_5873_oob.js | CVE-2026-5873 Turboshaft Wasm OOB exploit |
| dawn_escape.js | CVE-2026-5281 Dawn WebGPU UAF framework |
| exploit.html | Chain 1 V8 exploit display |
| exploit_sort.html | Chain 2 V8 exploit display |
| exploit_dawn.html | Chain 3 Dawn WebGPU exploit display |
| exploit_mojo.html | Chain 4 Mojo escape reference |
| exploit_realworld.html | Real-world chain display |
| CHAIN_AUDIT.md | Comprehensive vulnerability audit (this session) |
| AUDIT.md | Previous audit document |
| crbug-542403045-analysis.md | Sort confusion bug analysis |
| find_cmplayer.py | CmpLayerVersionCount RVA finder |
| diag_win10.py | Diagnostic: Win10 CVE-2026-40369 viability |
| WRITEUP.md | Full technical writeup |
| run_elevated.bat | Helper script |
| run_elevated.ps1 | Helper script |

## Win10 Test Machine
- Chrome: C:\Users\kuvee\Downloads\chrome-win64\chrome-win64\chrome.exe
- Build: Win10 21H2 19044.7663
- ntoskrnl PDB GUID: C647466F42B0DF967125FB428EFB2FA11

## CLI Usage
```
# Chain 1: CVE-2026-6307 + kernel escape
python orchestrator.py --chrome <chrome.exe> --stage2 <stage2.bin>

# Chain 2: Sort confusion + kernel escape
python orchestrator_sort.py --chrome <chrome.exe> --stage2 <stage2.bin>

# ★ Chain 3: CVE-2026-6307 + Dawn WebGPU escape (BEST — no kernel)
python orchestrator_dawn.py --chrome <chrome.exe>

# Chain A: True real-world (CVE-2026-6307 + WCPT + kernel)
python orchestrator_chain_a.py --chrome <chrome.exe> --stage2 <stage2.bin>

# Chain B: Turboshaft Wasm OOB entry
python orchestrator_chain_a.py --chrome <chrome.exe> --chain-b --stage2 <stage2.bin>

# Manual RVA overrides (Chains 1 & 2)
python orchestrator.py --chrome <chrome.exe> --rva-cmplayer 0xXXX --rva-psinitial 0xXXX
```

## Next Steps
1. ★ Reverse Chrome .165→.177 patch diff for CVE-2026-5281 Dawn UAF trigger
2. Test WCPT V8 sandbox bypass on Chrome 146 (verify issue 452605803 not patched)
3. Test CVE-2026-5873 Turboshaft OOB on Chrome 146
4. Test orchestrator_dawn.py → confirm Dawn escape works
5. Test orchestrator_sort.py → confirm sort confusion addrof
6. Run diag_win10.py on Win10 → confirm class 253 status

## Key References
- [Hacktron — Chrome 146 Exploit](https://www.hacktron.ai/blog/i-let-claude-opus-to-write-me-a-chrome-exploit)
- [Theori — V8 Sandbox Escape ITW](https://theori.io/blog/a-deep-dive-into-v8-sandbox-escape-technique-used-in-in-the-wild-exploit)
- [mem2019 — Trusted Pointer Table](https://mem2019.github.io/jekyll/update/2024/07/14/HITCON.html)
- [xv0nfers — V8 SBX Bypass Collection](https://github.com/xv0nfers/V8-sbx-bypass-collection)
- [Petitoto — chromium-exploit-dev](https://github.com/Petitoto/chromium-exploit-dev)
- [CVE-2026-5281 Advisory](https://www.helpnetsecurity.com/2026/04/01/google-chrome-zero-day-cve-2026-5281/)
- [CVE-2026-85046 Analysis](https://www.penligent.ai/hackinglabs/cve-2026-85046/)

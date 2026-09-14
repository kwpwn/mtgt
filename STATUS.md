# Full Chain Exploits — Status

## Target: Chrome 146.0.7680.165 / V8 14.6.202.26

---

## Chain 1: CVE-2026-6307 + CVE-2026-40369 (V8 RCE + Kernel)
- **Entry**: TurboFan FrameState CSE → addrof + fakeobj
- **Phases 1-6**: CONFIRMED on both Win10 & Win11
- **Renderer RCE**: Native code execution in sandboxed renderer (UNTRUSTED IL)
- **KASLR bypass**: EnumDeviceDrivers leaks ntoskrnl base from MEDIUM IL
- **PsInitialSystemProcess**: Found via PE export table (RVA 0x00cfc420 on Win10 21H2)
- **Stage2.bin**: 5805 bytes, sentinels verified, JMP/FPO correct
- **V8 SBX bypass**: Orchestrator-assisted (WPM from MEDIUM IL — NOT real-world)
- **Escape**: CVE-2026-40369 kernel exploit → SYSTEM
- **Limitation**: Win11-only (CmpLayerVersionCount)

## Chain 2: crbug-542403045 + CVE-2026-6307 + CVE-2026-40369 (Sort + Kernel)
- **Entry**: Array.prototype.sort element kind confusion → addrof
- **fakeobj**: CVE-2026-6307 FrameState CSE (same Chrome 146 version)
- **V8 SBX bypass**: Orchestrator-assisted (NOT real-world)
- **Escape**: CVE-2026-40369 kernel exploit → SYSTEM
- **Status**: Code written, NEEDS TESTING

## ★ Chain 3: CVE-2026-6307 + CVE-2026-5281 (V8 RCE + Dawn WebGPU Escape) ★
- **Entry**: TurboFan FrameState CSE → addrof + fakeobj
- **Escape**: Dawn WebGPU buffer.destroy() race → UAF in GPU process
- **CVE-2026-5281**: Fixed in 146.0.7680.178, our .165 IS VULNERABLE
- **NO V8 SBX bypass needed**: WebGPU API accessible from JS directly
- **NO kernel exploit needed**: Escapes via GPU process boundary
- **NO admin needed**: TRUE real-world exploit
- **Works on**: Win10 AND Win11 (no kernel dependency)
- **ITW**: Confirmed by CISA KEV, used in targeted attacks
- **Status**: Code written, NEEDS TESTING
- **Rating**: ★★★★★ BEST CHAIN

## Chain 4: CVE-2026-6307 + CVE-2026-8523 (V8 RCE + Mojo Escape)
- **Entry**: TurboFan FrameState CSE → addrof + fakeobj
- **V8 SBX bypass**: Required (Mojo needs native code for crafted IPC)
- **Escape**: Mojo IPC use-after-free → browser process (MEDIUM IL)
- **CVE-2026-8523**: Fixed in Chrome 148, our 146 IS VULNERABLE
- **Status**: Reference exploit written, orchestrator TODO
- **Rating**: ★★★★☆

## Chain 5: crbug-542403045 + CVE-2026-6307 + CVE-2026-5281 (Sort + Dawn)
- **Entry**: Sort element kind confusion → addrof + FrameState CSE → fakeobj
- **Escape**: Same Dawn WebGPU escape as Chain 3
- **Status**: Can be combined from existing code
- **Rating**: ★★★★☆

## Chain 6: CVE-2026-6307 + CVE-2026-14109 (V8 RCE + Mojo Policy)
- **Entry**: TurboFan FrameState CSE
- **V8 SBX bypass**: Required
- **Escape**: Mojo insufficient policy enforcement → browser process
- **CVE-2026-14109**: Fixed in Chrome 150, our 146 IS VULNERABLE
- **Status**: Research only
- **Rating**: ★★★☆☆

---

## Blocked (Chains 1 & 2 only)
- **CmpLayerVersionCount RVA**: NOT found on Win10 21H2 (Build 19044.7663)
  - Not in public PDB (symbol stripped)
  - Binary pattern scan (MOV [rsp+28h],0xFF8 + LEA) — NOT FOUND
  - **Root cause**: SystemLayerSnapshot (class 253) likely Win11-only
  - Need to run `diag_win10.py` on Win10 to confirm

## Pattern Scan (verified on Win11 25H2)
```
c7 44 24 28 f8 0f 00 00   MOV [rsp+28h], 0xFF8
48 8d 15 XX XX XX XX       LEA rdx, [rip+disp32]  -> CmpLayerVersionCount
```
- Win11 result: RVA 0x00ef709c (matches PDB)
- Win10 result: pattern not found

---

## Version Analysis: What's Exploitable on 146.0.7680.165

### Exploitable V8 RCE
- CVE-2026-6307 (FrameState CSE) — ✅
- crbug-542403045 (sort confusion, fix Chrome 152) — ✅
- CVE-2026-85046 (ITW, fix Chrome 152) — ✅ no public PoC
- CVE-2026-11645 (ITW, fix Chrome 149) — ✅ no public PoC

### Exploitable Sandbox Escapes
- CVE-2026-5281 (Dawn WebGPU, fix .178) — ✅ **BEST**
- CVE-2026-8523 (Mojo, fix Chrome 148) — ✅
- CVE-2026-14109 (Mojo, fix Chrome 150) — ✅

### NOT Exploitable (Patched)
- CVE-2026-3910 (Maglev Phi, fix .75) — ❌
- CVE-2026-4676 (Dawn, fix .165) — ❌
- CVE-2025-2783 (Mojo, fix Chrome 134) — ❌

---

## Files
| File | Location | Purpose |
|------|----------|---------|
| orchestrator.py | E:\CVE\mtgt\ | Chain 1 orchestrator (CVE-2026-6307 + kernel) |
| orchestrator_sort.py | E:\CVE\mtgt\ | Chain 2 orchestrator (sort + kernel) |
| orchestrator_dawn.py | E:\CVE\mtgt\ | Chain 3 orchestrator (V8 + Dawn escape) ★ |
| exploit.html | E:\CVE\mtgt\ | Chain 1 V8 exploit display |
| exploit_sort.html | E:\CVE\mtgt\ | Chain 2 V8 exploit display |
| exploit_dawn.html | E:\CVE\mtgt\ | Chain 3 Dawn WebGPU exploit display |
| exploit_mojo.html | E:\CVE\mtgt\ | Chain 4 Mojo escape reference |
| AUDIT.md | E:\CVE\mtgt\ | Comprehensive vulnerability audit |
| crbug-542403045-analysis.md | E:\CVE\mtgt\ | Sort confusion bug analysis |
| find_cmplayer.py | E:\CVE\mtgt\ | CmpLayerVersionCount RVA finder |
| diag_win10.py | E:\CVE\mtgt\ | Diagnostic: Win10 CVE-2026-40369 viability |
| stage2.bin | fullchain-windows-CVE-2026-6307-40369\ | Kernel shellcode (PIC) |
| stage2_pic.c | fullchain-windows-CVE-2026-6307-40369\ | Stage2 source |

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

# Chain 3: CVE-2026-6307 + Dawn WebGPU escape (★ BEST — no kernel needed)
python orchestrator_dawn.py --chrome <chrome.exe>

# Chain 3 with multiple UAF attempts
python orchestrator_dawn.py --chrome <chrome.exe> --attempts 10

# Manual RVA overrides (Chains 1 & 2 only)
python orchestrator.py --chrome <chrome.exe> --rva-cmplayer 0xXXX --rva-psinitial 0xXXX
```

## Next Steps
1. ★ Test orchestrator_dawn.py on Chrome 146 → confirm Dawn UAF triggers
2. Test orchestrator_sort.py → confirm sort confusion addrof works
3. Run `diag_win10.py` → confirm if class 253 exists on Win10
4. Research CVE-2026-8523 Mojo UAF details → build Chain 4 orchestrator
5. Investigate V8 SBX bypass techniques still alive on Chrome 146

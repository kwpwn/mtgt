# Chrome 146.0.7680.165 — Full Chain Vulnerability Audit

## Target
- **Chrome**: 146.0.7680.165 / V8 14.6.202.26
- **OS**: Windows 10/11
- **Goal**: RCE + Sandbox Escape (user already has separate LPE)

---

## Vulnerability Classification

### Category A: V8 RCE (Renderer Code Execution)

| # | CVE / Bug | Type | Fix Version | On 146.0.7680.165 | Public PoC |
|---|-----------|------|-------------|-------------------|------------|
| 1 | **CVE-2026-6307** | TurboFan FrameState CSE | >146 | ✅ EXPLOITABLE | ✅ Have exploit |
| 2 | **crbug-542403045** | Sort element kind confusion | Chrome 152 | ✅ EXPLOITABLE | ✅ Have exploit |
| 3 | **CVE-2026-85046** | Maglev+TurboFan type confusion | Chrome 152.0.7977.82 | ✅ EXPLOITABLE | ❌ No public PoC (ITW) |
| 4 | **CVE-2026-11645** | V8 OOB read/write | Chrome 149.0.7827.103 | ✅ EXPLOITABLE | ❌ No public PoC (ITW) |
| 5 | CVE-2026-3910 | Maglev Phi Untagging | 146.0.7680.75 | ❌ PATCHED (.165>.75) | — |
| 6 | CVE-2025-2135 | TurboFan alias confusion | Chrome 134 | ❌ PATCHED | — |
| 7 | CVE-2025-0291 | Turboshaft type confusion | Chrome 130 | ❌ PATCHED | — |

### Category B: Chrome Sandbox Escape

| # | CVE | Type | Fix Version | On 146.0.7680.165 | Requires V8 SBX bypass? |
|---|-----|------|-------------|-------------------|------------------------|
| 1 | **CVE-2026-5281** | Dawn WebGPU UAF | 146.0.7680.178 | ✅ EXPLOITABLE (.165<.178) | ❌ NO — WebGPU API from JS |
| 2 | **CVE-2026-8523** | Mojo IPC UAF | Chrome 148.0.7778.168 | ✅ EXPLOITABLE | ✅ YES — needs native code |
| 3 | **CVE-2026-14109** | Mojo policy bypass | Chrome 150.0.7871.47 | ✅ EXPLOITABLE | ✅ YES — needs native code |
| 4 | CVE-2026-4676 | Dawn WebGPU UAF | 146.0.7680.165 | ❌ PATCHED (exact ver) | — |
| 5 | CVE-2025-2783 | Mojo IPC handle | Chrome 134 | ❌ PATCHED | — |

### Category C: V8 Sandbox Bypass

| # | Issue/Technique | Type | Status on Chrome 146 |
|---|----------------|------|---------------------|
| 1 | Issue 421403261 (Liftoff hash collision) | WASM Liftoff | ⚠️ NEEDS TESTING (134-137 range) |
| 2 | Issue 391169061 (TypedArray::set overflow) | Integer overflow | ⚠️ NEEDS VERSION CHECK |
| 3 | Issue 344963941 (Irregexp bytecode mod) | Regex engine | ⚠️ NEEDS VERSION CHECK |
| 4 | Issue 352689356 (WASM func sig confusion) | TurboFan call_ref | ❌ Likely patched (≤131) |
| 5 | Issue 379140430 (Tuple2 tier-up) | WASM tier-up | ❌ Likely patched (≤132) |
| 6 | Issue 395659804 (DeoptimizationData) | OSR confusion | ❌ Likely patched (≤134) |
| 7 | ReadableStream TOCTOU | WASM streaming | ❌ Patched (Chrome 139) |

### Category D: Kernel LPE

| # | CVE | Type | Status |
|---|-----|------|--------|
| 1 | **CVE-2026-40369** | CmpLayerVersionCount confusion | ✅ Win11 only, have exploit |

---

## Full Chains

### Chain 1 (Existing): V8 RCE + Kernel Escape
```
CVE-2026-6307 (FrameState CSE) → addrof/fakeobj
  → V8 SBX bypass: Orchestrator WPM (NOT real-world)
  → WASM JIT hijack → native shellcode in renderer
  → CVE-2026-40369 kernel exploit → SYSTEM
```
- **Files**: orchestrator.py, exploit.html
- **Rating**: ★★★☆☆
- **Limitation**: V8 SBX bypass is orchestrator-assisted, Win11-only

### Chain 2 (Existing): Sort + V8 RCE + Kernel Escape
```
crbug-542403045 (sort confusion) → addrof_compressed
  + CVE-2026-6307 (FrameState CSE) → fakeobj
  → V8 SBX bypass: Orchestrator WPM (NOT real-world)
  → WASM JIT hijack → native shellcode
  → CVE-2026-40369 kernel exploit → SYSTEM
```
- **Files**: orchestrator_sort.py, exploit_sort.html
- **Rating**: ★★★☆☆
- **Limitation**: Same as Chain 1

### Chain 3 (NEW — BEST): V8 RCE + Dawn WebGPU Escape ★★★★★
```
CVE-2026-6307 (FrameState CSE) → addrof/fakeobj
  → WebGPU API calls from JavaScript (NO V8 SBX bypass needed!)
  → CVE-2026-5281 (Dawn buffer.destroy() race)
  → UAF in GPU process → heap spray → code exec in GPU process
  → Sandbox escape: GPU process > renderer privilege
```
- **Files**: orchestrator_dawn.py, exploit_dawn.html
- **Rating**: ★★★★★ TRUE REAL-WORLD
- **Why best**: NO admin, NO kernel, NO V8 SBX bypass needed, works on Win10+Win11

### Chain 4 (NEW): V8 RCE + Mojo UAF Escape
```
CVE-2026-6307 (FrameState CSE) → addrof/fakeobj
  → V8 SBX bypass (needed for Mojo)
  → CVE-2026-8523 (Mojo IPC UAF)
  → Sandbox escape to browser process (MEDIUM IL)
```
- **Files**: exploit_mojo.html (orchestrator TODO)
- **Rating**: ★★★★☆
- **Note**: Requires V8 sandbox bypass; browser process at MEDIUM IL = strong escape

### Chain 5 (NEW): Sort + V8 RCE + Dawn Escape
```
crbug-542403045 (sort confusion) → addrof_compressed
  + CVE-2026-6307 (FrameState CSE) → fakeobj
  → WebGPU API → CVE-2026-5281 (Dawn UAF) → sandbox escape
```
- **Files**: Uses orchestrator_dawn.py with sort confusion entry
- **Rating**: ★★★★☆
- **Note**: Variant of Chain 3 with different entry point

### Chain 6 (NEW): V8 RCE + Mojo Policy Escape
```
CVE-2026-6307 → V8 SBX bypass → native code
  → CVE-2026-14109 (Mojo insufficient policy enforcement)
  → Sandbox escape to browser process
```
- **Files**: (TODO)
- **Rating**: ★★★☆☆
- **Note**: Less public info available about CVE-2026-14109

---

## Key Finding: CVE-2026-5281 Dawn WebGPU UAF

**This is the most important finding of the audit.**

CVE-2026-5281 provides sandbox escape from the renderer to the GPU process
through the WebGPU API, which is accessible from pure JavaScript.
This means NO V8 sandbox bypass is needed — the V8 exploit primitives
(addrof/fakeobj) are useful but not strictly required for the escape stage.

### Technical Details
- **Root cause**: Race between buffer.destroy() and in-flight GPU commands
- **Affected object**: GPUBuffer lifecycle in Dawn's command submission path  
- **Trigger**: Destroy buffers while compute shaders reference them → dangling VRAM pointer
- **Exploitation**: Heap spray GPU process memory via new buffer allocations
- **Fix**: Chrome 146.0.7680.178 (our .165 is BEFORE this)
- **ITW**: Confirmed by CISA KEV; used in targeted attacks against Saudi financial sector
- **GitHub**: TheMalwareGuardian/CVE-2026-5281 (analysis + lab tools)

---

## Vulnerability Sources
- NIST NVD, CISA KEV catalog
- Chrome release notes / security advisories
- TheMalwareGuardian/CVE-2026-5281 (GitHub)
- xv0nfers/V8-sbx-bypass-collection (GitHub)
- Petitoto/chromium-exploit-dev (GitHub)
- Theori: V8 Sandbox Escape ITW technique
- mem2019: Breaking V8 Sandbox with TPT (HITCON 2024)
- SSD Disclosure: ReadableStream TOCTOU
- Zellic: CVE-2025-2135 writeup
- exploit-intel.com, socprime.com, penligent.ai, BleepingComputer, TheHackerNews

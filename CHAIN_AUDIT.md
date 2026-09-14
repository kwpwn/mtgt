# Chrome 146.0.7680.165 Full Chain Exploit Audit

**Target**: Chrome 146.0.7680.165 / V8 14.6.202.26 / Windows 11 Build 26200
**Date**: 2026-09-14
**Objective**: Real-world sandbox escape — NO admin, NO orchestrator-assisted WPM/RPM

---

## VULNERABILITY INVENTORY

### A. RCE (V8 / Renderer Code Execution inside V8 cage)

| # | CVE | Component | Type | Fixed In | Status | Notes |
|---|-----|-----------|------|----------|--------|-------|
| 1 | CVE-2026-6307 | V8 TurboFan | FrameState CSE confusion | 147.0.7727.101 | **CONFIRMED** | "Longinus" — addrof+fakeobj with full 64-bit pointers |
| 2 | CVE-2026-85046 (=crbug-542403045) | V8 Maglev+TurboFan | Sort element kind confusion | 152.0.7977.82 | **CODE WRITTEN** | ITW 0day. addrof via sort, fakeobj via write barrier skip |
| 3 | CVE-2026-11645 | V8 | OOB read/write | 149.0.7827.102 | Vulnerable | ITW 0day. $55k bounty |
| 4 | CVE-2026-87491 | V8 | OOB write | 153.0.8010.36 | Vulnerable | ITW 0day. 7th of 2026 |
| 5 | CVE-2026-5865 | V8 TurboFan | Type confusion | 147.0.7727.x | Vulnerable | |
| 6 | CVE-2026-5871 | V8 TurboFan | Type confusion | 147.0.7727.x | Vulnerable | |
| 7 | CVE-2026-7899 | V8 | OOB read/write | 148.0.7778.96 | Vulnerable | $55k bounty |
| 8 | CVE-2026-5858 | WebML | Heap buffer overflow | 147.0.7727.x | Vulnerable | Critical. $43k bounty |
| 9 | CVE-2026-6296 | ANGLE | Heap buffer overflow | 147.0.7727.101 | Vulnerable | Critical. $90k bounty |
| 10 | CVE-2026-6301 | V8 TurboFan | Type confusion | 147.0.7727.101 | Vulnerable | |

### B. V8 Sandbox Bypass (escape V8 cage → full renderer R/W)

| # | CVE | Technique | Fixed In | Status | Notes |
|---|-----|-----------|----------|--------|-------|
| 1 | **CVE-2026-6307** | Full 64-bit fakeobj bypasses cage | 147.0.7727.101 | **CONFIRMED** | Same bug as RCE! fakeobj reaches outside 4GB cage |
| 2 | CVE-2026-10904 | "Inappropriate implementation" V8 SBX | 149.0.7827.53 | Vulnerable | Bug 506855825. Sparse details |

**KEY FINDING**: CVE-2026-6307 is BOTH the RCE AND the V8 sandbox bypass. The
FrameState CSE confusion produces full 64-bit uncompressed pointers via the WASM-JS
boundary. `fakeobj(addr)` materializes objects at arbitrary 64-bit addresses, reaching
outside the V8 sandbox cage. No separate EPT/CPT/TPT bypass needed.

### C. Chrome Sandbox Escape (renderer → OS level code execution)

| # | CVE | Component | Type | Fixed In | Status | Notes |
|---|-----|-----------|------|----------|--------|-------|
| 1 | **CVE-2026-5281** | Dawn (WebGPU) | UAF | 146.0.7680.177 | **VULNERABLE** | ITW 0day! Fix at .177, target is .165 |
| 2 | CVE-2026-8580 | Mojo IPC | UAF | 148.0.7778.168 | Vulnerable | Critical CVSS 9.6. Full sandbox escape |
| 3 | CVE-2026-10881 | ANGLE | OOB R/W | 149.0.7827.53 | Vulnerable | Critical CVSS 9.6. $97k bounty |
| 4 | CVE-2026-14109 | Mojo IPC | Policy enforcement | 150.0.7871.47 | Vulnerable | Critical CVSS 9.6 |
| 5 | CVE-2026-7350 | WebMIDI | UAF | 147.0.7727.137 | Vulnerable | Sandbox escape |
| 6 | CVE-2026-7923 | Skia | Unknown | 148.0.7778.167 | Vulnerable | Sandbox escape |
| 7 | CVE-2026-11660 | New Tab Page IPC | Unknown | 149.0.7827.102 | Vulnerable | Sandbox escape |

### D. Kernel LPE (NOT needed for real-world chain, user has separate LPE)

| # | CVE | Notes |
|---|-----|-------|
| 1 | CVE-2026-40369 | CmpLayerVersionCount confusion. Win11-only. Already have stage2.bin |

---

## FULL CHAIN CANDIDATES

### ═══ CHAIN 1 (BEST): CVE-2026-6307 + CVE-2026-5281 ═══
**Rating: ★★★★★ — Real-world, NO admin, NO kernel**

| Stage | CVE | Component | Role |
|-------|-----|-----------|------|
| RCE + V8 SBX bypass | CVE-2026-6307 | V8 TurboFan FrameState CSE | Full 64-bit addrof/fakeobj |
| Chrome SBX escape | CVE-2026-5281 | Dawn WebGPU UAF | Renderer → GPU process escape |

```
Stage 1: CVE-2026-6307 (V8 RCE + V8 Sandbox Bypass — SINGLE BUG)
  JS → TurboFan FrameState CSE confusion
  → Incomplete equality in FrameStateFunctionInfo (omits signature_)
  → externref/i64 return type conflation during deopt
  → addrof: deoptimizer reads tagged ref as raw i64 → full 64-bit address
  → fakeobj: deoptimizer treats i64 as tagged ref WITHOUT validation
  → NO pointer table lookup → bypasses EPT, CPT, TPT
  → JIT code staging: shellcode as float64 constants in JIT code
  → Property store on fakeobj → patches JMP into JIT code
  → Native code execution in renderer (UNTRUSTED IL)

Stage 2: CVE-2026-5281 (Dawn WebGPU UAF → Browser Sandbox Escape)
  → Allocate 200 GPUBuffers, create bind groups (stale refs)
  → Submit 48 heavy compute batches → GPU queue saturated
  → buffer.destroy() → Dawn frees native objects
  → Bind groups retain stale pointers (bypasses CVE-2026-4676 fix)
  → Heap spray: reclaim freed objects with controlled data
  → GPU processes stale commands → UAF in GPU process
  → Vtable hijack → code execution at GPU process privilege
```

**Advantages:**
- NO kernel exploit needed — escapes directly to GPU process
- NO admin privileges — entirely from web page
- NO separate V8 SBX bypass needed — CVE-2026-6307 IS the bypass
- NO WCPT, no EPT corruption, no CPT bypass
- Works on Windows AND Linux AND macOS (cross-platform)
- Both CVEs confirmed on Chrome 146.0.7680.165
- CVE-2026-5281 was exploited ITW (proven weaponizable)
- CVE-2026-6307 has public PoC code + Nebula Security writeup
- 100% success rate for addrof/fakeobj (deterministic deopt path)

---

### ═══ CHAIN 2: CVE-2026-6307 + CVE-2026-8580 ═══
**Rating: ★★★★☆ — Mojo IPC sandbox escape**

| Stage | CVE | Component | Role |
|-------|-----|-----------|------|
| RCE + V8 SBX | CVE-2026-6307 | V8 TurboFan | Full 64-bit R/W |
| Chrome SBX escape | CVE-2026-8580 | Mojo IPC | UAF → browser process |

CVSS 9.6 for the Mojo bug. Full sandbox escape from renderer to browser process.

---

### ═══ CHAIN 3: CVE-2026-6307 + CVE-2026-10881 ═══
**Rating: ★★★★☆ — ANGLE OOB sandbox escape**

| Stage | CVE | Component | Role |
|-------|-----|-----------|------|
| RCE + V8 SBX | CVE-2026-6307 | V8 TurboFan | Full 64-bit R/W |
| Chrome SBX escape | CVE-2026-10881 | ANGLE | OOB R/W → sandbox escape |

$97k bounty, CVSS 9.6. OOB read/write in ANGLE (OpenGL ES abstraction layer).

---

### ═══ CHAIN 4: CVE-2026-6307 + CVE-2026-14109 ═══
**Rating: ★★★☆☆ — Mojo policy bypass**

| Stage | CVE | Component | Role |
|-------|-----|-----------|------|
| RCE + V8 SBX | CVE-2026-6307 | V8 TurboFan | Full 64-bit R/W |
| Chrome SBX escape | CVE-2026-14109 | Mojo IPC | Policy enforcement bypass |

---

### ═══ CHAIN 5: crbug-542403045 + CVE-2026-6307 + CVE-2026-5281 ═══
**Rating: ★★★★☆ — Sort confusion entry, same escape**

| Stage | CVE | Component | Role |
|-------|-----|-----------|------|
| RCE (addrof) | CVE-2026-85046 | V8 Sort confusion | addrof via Smi/HeapObj confusion |
| V8 SBX (fakeobj) | CVE-2026-6307 | TurboFan FrameState | Full 64-bit fakeobj |
| Chrome SBX escape | CVE-2026-5281 | Dawn WebGPU UAF | Renderer → GPU process |

Alternative RCE entry using the sort confusion (ITW 0day).

---

### ═══ CHAIN 6: CVE-2026-6307 + CVE-2026-40369 (EXISTING) ═══
**Rating: ★★☆☆☆ — Orchestrator-assisted, NOT real-world**

Our CURRENT Chain 1. Orchestrator uses WriteProcessMemory from MEDIUM IL to write
shellcode into renderer JIT pages. NOT a true sandbox escape. Code: orchestrator.py

---

### ═══ CHAIN 7: crbug-542403045 + CVE-2026-6307 + CVE-2026-40369 (EXISTING) ═══
**Rating: ★★☆☆☆ — Orchestrator-assisted, NOT real-world**

Same as Chain 6 with sort confusion entry. Code: orchestrator_sort.py

---

## CRITICAL PATH: CVE-2026-6307 V8 Sandbox Bypass (Nebula Security Technique)

CVE-2026-6307 is BOTH the RCE AND the V8 sandbox bypass. No separate bypass needed.

### Root Cause (from Nebula Security writeup)
```
The equality operator in FrameStateFunctionInfo checked parameter_count,
local_count, and shared_info — but OMITTED the signature_ field from
JSToWasmFrameStateFunctionInfo. Two functions with signatures () -> externref
and () -> i64 appear identical to CSE. One FrameState is eliminated; deopt
data uses the survivor's return_kind for both.
```

### addrof: Object → Full 64-bit Address
Deoptimizer reads tagged reference from return register as raw i64.
Materializes it as BigInt exposing full pointer bits. 100% success rate.
```javascript
let addr = addrof(target);  // Full 64-bit BigInt, NOT cage-relative
```

### fakeobj: 64-bit Address → JS Object
Deoptimizer treats attacker's i64 as tagged JavaScript reference WITHOUT
validation or compression. No pointer table lookup occurs.
```javascript
let obj = fakeobj(0x7ff0deadbeefn);  // Object anywhere in process memory
```

### V8 Sandbox Bypass Mechanism
The forged reference bypasses ALL V8 sandbox indirection:
- ExternalPointerTable (EPT): not consulted — bits are direct tagged ref
- CodePointerTable (CPT): not consulted — same reason
- TrustedPointerTable (TPT): not consulted — same reason
- Compression cage: irrelevant — fakeobj uses full 64-bit address

### JIT Code Staging (Nebula Technique)
1. Embed shellcode bytes as float64 constants in JIT-compiled function
2. TurboFan compiles constants as raw 64-bit immediates in code stream
3. Constants are already in an executable page — just need a JMP
4. Property store on fakeobj writes at (faked_addr + property_offset)
5. Write JMP instruction into JIT code before staged constants
6. Call function → JMP → execute shellcode doubles as x86-64

### Property Store Exploit
```
During warmup: r.p = v only executes on actual objects.
TurboFan optimizes as standard in-object property store.
On final invocation with forged pointer, property store
executes relative to attacker-controlled address.
```

### Dawn WebGPU Escape (CVE-2026-5281)
Bug 491518608 — variant of CVE-2026-4676, bypasses incomplete fix.
The CVE-2026-4676 fix added buffer ref counting, but bind groups
retain stale Dawn-internal refs after buffer.destroy().

1. Allocate 200 GPUBuffers (16KB STORAGE), create bind groups
2. Submit 48 compute batches with 8192 workgroups (GPU saturated)
3. buffer.destroy() all — Dawn frees native objects
4. Bind groups still hold stale pointers (bypass of 4676 fix)
5. Heap spray: 200 same-size buffers with 0x42424242 pattern
6. GPU processes stale commands → UAF in GPU process
7. Vtable hijack → code execution at GPU process privilege

---

## IMPLEMENTATION STATUS

### orchestrator_realworld.py — 2-STAGE CHAIN (SIMPLIFIED)
- Stage 1: CVE-2026-6307 (RCE + V8 SBX bypass via JIT staging)
- Stage 2: CVE-2026-5281 (Dawn UAF → GPU process escape)
- Eliminated WCPT stage — CVE-2026-6307 IS the V8 SBX bypass
- **File**: orchestrator_realworld.py

### dawn_escape.js — STANDALONE Dawn UAF TRIGGER
- Full WebGPU lifecycle exploitation with bind group stale refs
- Multiple race wave cycles for reliability
- Device lost detection for UAF confirmation
- **File**: dawn_escape.js

### exploit_realworld.html — CHAIN DESCRIPTION PAGE
- Technical breakdown of 2-stage architecture
- **File**: exploit_realworld.html

---

## PATCHED / NOT USABLE (for reference)

| CVE | Why not usable | Fixed In |
|-----|---------------|----------|
| CVE-2025-2135 | Chrome < 134 (patched) | 134.0.6998.88 |
| CVE-2025-2783 | Chrome < 134 (patched) | 134.0.6998.177 |
| CVE-2025-0291 | Chrome < 131 (patched) | Chrome 131 |
| CVE-2026-4676 | Fixed IN our target (.165) | 146.0.7680.165 |
| CVE-2026-3910 | Fixed at .75 (.165 > .75) | 146.0.7680.75 |
| CVE-2026-4447 | Fixed at .153 (.165 > .153) | 146.0.7680.153 |
| Petitoto SBX #1 (352689356) | Chrome ≤131 | Chrome 132 |
| Petitoto SBX #2 (379140430) | Chrome ≤132 | Chrome 133 |
| Petitoto SBX #3 (395659804) | Chrome ≤134 | Chrome 135 |
| Petitoto SBX #4 (421403261) | Chrome 134-137 | Chrome 138 |

---

## SOURCES

- CVE-2026-6307 writeup: https://nebusec.ai/research/v8-cve-2026-6307-writeup/
- CVE-2026-6307 PoC: https://github.com/J4ck3LSyN-Gen2/CVE-2026-6307-Longinus
- CVE-2026-85046 writeup: https://serotav.github.io/Writeups/v8/when-sorting-leads-to-confusion/
- CVE-2026-5281 analysis: https://github.com/TheMalwareGuardian/CVE-2026-5281
- CVE-2026-10904: https://issues.chromium.org/issues/506855825
- V8 sandbox bypasses: https://github.com/xv0nfers/V8-sbx-bypass-collection
- V8 sandbox design: https://v8.dev/blog/sandbox
- Theori V8 SBX ITW: https://theori.io/blog/a-deep-dive-into-v8-sandbox-escape-technique-used-in-in-the-wild-exploit
- Anvbis V8 heap sandbox: https://anvbis.au/posts/code-execution-in-chromiums-v8-heap-sandbox/

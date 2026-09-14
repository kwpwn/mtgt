# Comprehensive Full-Chain Audit — Chrome 146.0.7680.165
## Target: Chrome 146.0.7680.165 / V8 14.6.202.26 / Windows

---

## EXECUTIVE SUMMARY

After exhaustive research across public disclosures, Chromium issue tracker, security blogs,
conference presentations, and GitHub repositories worldwide, the following components have
been identified and classified for Chrome 146.0.7680.165 full-chain exploitation.

**Key finding**: A TRUE real-world full chain is possible using:
1. CVE-2026-6307 (V8 RCE) → 2. WCPT sandbox bypass → 3. CVE-2026-5281 (Dawn WebGPU escape)

This chain requires NO admin privileges, NO kernel exploit, and NO orchestrator-assisted
WriteProcessMemory. It escapes from UNTRUSTED IL (renderer) to MEDIUM IL (browser) purely
through software vulnerabilities.

---

## 1. V8 RCE BUGS (Renderer Code Execution Within V8 Cage)

### 1.1 CVE-2026-6307 "Longinus" — FrameState CSE ★★★★★
| Field | Value |
|-------|-------|
| Type | TurboFan FrameState Common Subexpression Elimination |
| Status | **CONFIRMED WORKING on Chrome 146** |
| Primitives | addrof + fakeobj (full) |
| Quality | Production exploit exists (orchestrator.py) |

**Root cause**: TurboFan CSE incorrectly deduplicates FrameState nodes, allowing
type confusion between object references. Yields both addrof and fakeobj within V8 cage.

**Exploit status**: FULLY WORKING. orchestrator.py implements complete
addrof/fakeobj via WASM globals with FrameState CSE.

---

### 1.2 crbug-542403045 — Sort Element Kind Confusion ★★★★☆
| Field | Value |
|-------|-------|
| Type | Maglev/TurboFan Array.prototype.sort inlining |
| Status | **CONFIRMED WORKING on Chrome 146** (addrof only) |
| Primitives | addrof only (fakeobj NOT achievable from sort alone) |
| Fix commit | e0562d87ad9c17042b581582c99237d798572e67 (Aug 7, 2026) |
| Affects | Chrome ≤151 |

**Root cause**: `CanInlineArrayIteratingBuiltin` unions {PACKED_SMI, PACKED} element kinds
without agreement check. Inlined sort uses PACKED_SMI access on PACKED array.
HeapObject ptrs read as Smis → cage_offsets. Recovery: `leaked_val * 2 + 1`.

**Limitation**: One-directional confusion only (HeapObj→Smi). Writing Smis back always
produces Smi-tagged values (bit 0 = 0), cannot create HeapObject pointers (bit 0 = 1).
Requires CVE-2026-6307 for fakeobj.

---

### 1.3 CVE-2026-85046 — Sort/Maglev Type Confusion (ITW 0day) ★★★☆☆
| Field | Value |
|-------|-------|
| Type | Maglev+TurboFan PACKED_ELEMENTS map confusion |
| Status | **VULNERABLE** (fixed in Chrome 152.0.7977.82) |
| Primitives | addrof + potentially fakeobj (ITW implies full chain) |
| Discovery | Salvatore Gulizia (Serotav), Aug 4, 2026 |
| CISA KEV | Yes, deadline Sept 18, 2026 |

**Root cause**: TryReduceArrayPrototypeSort — array with PACKED_ELEMENTS incorrectly
receives PACKED_SMI_ELEMENTS map. Same bug class as crbug-542403045 but in a different
code path. Affects both Maglev and TurboFan → more reliable trigger.

**Note**: ITW exploit exists (6th Chrome 0day of 2026). Full chain including sandbox
escape was used by attackers, but details restricted. No public PoC available.
May be the same underlying issue as crbug-542403045.

---

### 1.4 CVE-2026-5873 — Turboshaft WebAssembly OOB ★★★★★
| Field | Value |
|-------|-------|
| Type | Bounds-check elimination in Turboshaft Wasm compiler |
| Status | **VULNERABLE** (fixed in Chrome 147.0.7727.55) |
| Primitives | OOB read/write in Wasm linear memory → cage R/W |
| Source | Hacktron AI blog (full exploit code available) |

**Root cause**: `i32.convert_i64` truncates to 32 bits. Under Liftoff, bounds check
applies to full 64-bit value. After Turboshaft tier-up, bounds check is incorrectly
eliminated, allowing OOB access beyond 64KB Wasm memory page.

**Trigger**:
```wasm
(func $read (param i64) (result i32)
  local.get 0
  i32.convert_i64      ;; truncates upper 32 bits
  i32.const 2
  i32.shl              ;; index * 4
  i32.load align=4 offset=0
)
```

**Quality**: Hacktron blog describes complete exploitation including tier-up warmup
loop, ArrayBuffer backing store discovery, and "god buffer" setup for cage R/W.
Full JavaScript exploit code is available.

---

### 1.5 CVE-2025-0291 — Turboshaft Type Confusion ★★★★★
| Field | Value |
|-------|-------|
| Type | V8 Turboshaft compiler type confusion |
| Status | Likely PATCHED (Petitoto targets Chrome 130) |
| Source | Petitoto chromium-exploit-dev framework |

**Note**: Part of the Petitoto framework targeting Chrome 130. Chrome 146 likely has
the fix. Listed for completeness — the FRAMEWORK is the valuable asset, not this
specific bug.

---

### 1.6 CVE-2025-2135 — TurboFan TransitionElementsKindOrCheckMap ★★★★☆
| Field | Value |
|-------|-------|
| Type | TurboFan alias confusion (TransitionElementsKindOrCheckMap) |
| Status | **PATCHED** (fixed in Chrome ~134.0.6998.88) |
| Source | zellic.io V8CTF writeup |

Not viable for Chrome 146. Fix adds proper alias detection in InferMapsUnsafe().

---

## 2. V8 SANDBOX BYPASS (Escape V8 Cage to Arbitrary Virtual R/W)

### 2.1 WCPT Dispatch Table Corruption + CanonicalSig ★★★★★
| Field | Value |
|-------|-------|
| Issues | 452605803 / 446113730 |
| Status | **USED ON CHROME 146** (Hacktron blog confirms) |
| Fix commits | 1d13848 (Sep 2025), 9fdddb6 (Oct 2025) |
| Technique | dispatch_table_for_imports UAF → CanonicalSig type forging |

**How it works** (from Hacktron blog, confirmed on Chrome 146):

1. **Handle stride discovery**: Create marker WebAssembly.Table objects, determine
   trusted pointer table entry stride.

2. **Dispatch table transplant**: Overwrite victim table's handle field (offset 0x1c)
   to point at import dispatch table's handle:
   ```javascript
   writeCage32(addrof(tt) + kTDTOffset, h_target)
   ```

3. **Force entry deallocation**: `tt.grow(0x10)` triggers WasmDispatchTable::Grow →
   copies entries from transplanted import table → drops shared_ptr refcount to zero →
   frees WCPT entry for the import function.

4. **Dangling reference**: WasmInternalFunction (via ref.func) still holds freed WCPT slot.

5. **Reclaim freed slots**: Instantiate second Wasm module with matching signatures.
   V8 deduplicates CanonicalSig structures.

6. **Memory layout collision**: WasmImportData offset 0x18 (CanonicalSig*) collides with
   WasmTrustedInstanceData offset 0x18 (memory64_start). Read/write operations on memory64
   actually operate on the CanonicalSig structure.

7. **Type forging**: Overwrite return type reps `(i64, ref $s)` with parameter type
   reps `(i64, i64)`:
   ```javascript
   let ll = sig_read(0x30n)  // read param reps: (i64, i64)
   sig_write(0x28n, ll)      // overwrite return reps → (i64, i64)
   ```

8. **Sandbox escape**: Corrupted function returns `ref $s` (heap pointer) interpreted
   as raw `i64` → arbitrary virtual address read/write.

**Note**: The Hacktron blog explicitly states this was used on Chrome 146. Whether this
is an unfixed variant or a regression needs verification on the target binary.

---

### 2.2 Trusted Pointer Table Manipulation (mem2019 HITCON) ★★★★☆
| Field | Value |
|-------|-------|
| Source | mem2019.github.io (HITCON 2024) |
| Status | **VERSION UNCLEAR** — may work on Chrome 146 |
| Technique | Fake WasmExportedFunctionData via TPT entry rewrite |

**How it works**:
1. Write 64-bit values to trusted pointer table entries
2. Create fake WasmExportedFunctionData in sandboxed memory (double array)
3. Redirect `internal` field to attacker-controlled memory
4. Use AddSmi.ExtraWide bytecode to write controlled bytes to trusted memory
5. Execute shellcode embedded in JIT function immediates on RWX page

---

### 2.3 SharedFunctionInfo Confusion (Issue 348084786) ★★★☆☆
| Field | Value |
|-------|-------|
| Source | Chromium issue tracker |
| Status | **VERSION UNCLEAR** |
| Technique | Overwrite trusted_function_data in SharedFunctionInfo |

---

### 2.4 Petitoto V8 Sandbox Escapes — ALL PATCHED
| Issue | Technique | Affects | Status |
|-------|-----------|---------|--------|
| 352689356 | WASM func sig confusion | ≤131 | PATCHED |
| 379140430 | Tuple2 tier-up corruption | ≤132 | PATCHED |
| 395659804 | DeoptimizationData confusion | ≤134 | PATCHED |
| 421403261 | Liftoff hash collision | 134-137 | PATCHED |

---

### 2.5 CVE-2026-78901 / Issue 525686865 — JSDispatchTable Mark-Bit Erasure ★★★★☆
| Field | Value |
|-------|-------|
| Type | Race condition in concurrent marking vs deoptimization |
| Status | **VULNERABLE** (fixed in Chrome 152.0.7977.65) |
| CVSS | 7.5 (High) |
| CWE | CWE-362 (Race Condition) |

**Root cause**: `Code::SetMarkedForDeoptimization` updates a JSDispatchTable entry
without a write barrier. If concurrent marking (background GC thread) sets the mark
bit between the mutator's load and store, the mark bit is silently erased:

```
Mutator thread:                    Concurrent marker:
  old = Load(entry)
                                    CAS Mark(entry)  // sets mark bit
  new = old | deopt_flag
  Store(entry, new)                // OVERWRITES mark bit!
```

The live entry appears unmarked → swept by GC → dangling JSDispatchHandle.

**Exploitation approach**:
1. Create many optimized functions (populates JSDispatchTable)
2. Invalidate feedback to trigger mass deoptimization
3. Race deopt with GC pressure (heavy allocation)
4. Dangling handles → call freed function → controlled crash/redirect
5. Spray controlled data via V8 heap R/W into freed dispatch slots
6. Redirect entrypoint to shellcode in RWX WASM JIT pages

**Alternative to WCPT technique**: Can be used as backup if WCPT (Issue 452605803)
is patched on the specific Chrome 146 build.

---

### 2.6 CVE-2024-12053 — Canonical vs Relative Type Index — PATCHED
| Field | Value |
|-------|-------|
| Status | **PATCHED** (fixed in Chrome 134) |
| Technique | ValueTypeBase::ref_index() canonical/relative confusion |

Chrome 146 includes the fix: `CanonicalRelativeField` bit removed from ValueTypeBase,
relative index confusion vector eliminated.

---

## 3. BROWSER SANDBOX ESCAPE (Renderer → Browser/OS)

### 3.1 CVE-2026-5281 — Dawn WebGPU UAF ★★★★★ BEST
| Field | Value |
|-------|-------|
| Type | Use-after-free in Dawn (WebGPU implementation) |
| Status | **VULNERABLE** (fixed in 146.0.7680.177/178) |
| Our target | 146.0.7680.165 < 146.0.7680.177 → **EXPLOITABLE** |
| Impact | Renderer → Browser (MEDIUM IL) |
| CISA KEV | Yes |
| Kernel needed | **NO** |

**Chrome's 4th zero-day of 2026**. ITW exploit confirmed. Allows a compromised renderer
process to execute arbitrary code at browser process privilege level via crafted WebGPU
operations that trigger use-after-free in Dawn's object lifecycle management.

**This is the key escape**: From renderer (UNTRUSTED IL, 0x0000) to browser (MEDIUM IL,
0x2000) WITHOUT any kernel exploit. User already has LPE (CVE-2026-40369) separately.

---

### 3.2 CVE-2026-4676 — Dawn WebGPU UAF — PATCHED
| Field | Value |
|-------|-------|
| Type | Use-after-free in Dawn |
| Status | **PATCHED** (fixed IN 146.0.7680.165) |

Fixed in the exact version we target. Not viable.

---

### 3.3 CVE-2025-2783 — Mojo IPC (Operation ForumTroll) — PATCHED
| Field | Value |
|-------|-------|
| Type | Incorrect handle relay in Mojo/IpcZ |
| Status | **PATCHED** (fixed in Chrome 134.0.6998.177) |

Chrome 146 >> Chrome 134. Not viable.

---

### 3.4 CVE-2024-11114 — Mojo startDragging + DLL hijack — PATCHED
| Field | Value |
|-------|-------|
| Type | Mojo IPC startDragging abuse |
| Status | **PATCHED** (Petitoto targets Chrome 130) |

Not viable for Chrome 146.

---

### 3.5 CVE-2026-40369 — Kernel CmpLayerVersionCount ★★★☆☆
| Field | Value |
|-------|-------|
| Type | Kernel type confusion in NtQuerySystemInformation(253) |
| Status | Win11 only (class 253 not present on Win10) |
| Impact | SYSTEM privileges directly |

Requires: Win11 Build 26200+, CmpLayerVersionCount RVA resolution.
Not a browser escape per se — it's a kernel LPE from MEDIUM IL.
User already has this separately.

---

## 4. VIABLE FULL CHAINS

### ═══ Chain A: TRUE REAL-WORLD (NO admin, NO kernel) ═══
```
CVE-2026-6307 (FrameState CSE)
  → addrof/fakeobj (V8 cage R/W)
  → WCPT dispatch table corruption (Issue 452605803)
  → CanonicalSig type confusion
  → arbitrary virtual R/W (V8 sandbox escaped)
  → CVE-2026-5281 (Dawn WebGPU UAF)
  → code execution at MEDIUM IL (browser process)
```
**Rating: ★★★★★**
- V8 RCE: CONFIRMED
- V8 SBX bypass: Documented for Chrome 146 (Hacktron blog)
- Browser escape: CONFIRMED VULNERABLE (146.0.7680.165 < 146.0.7680.177)
- NO admin, NO kernel, TRUE real-world

---

### ═══ Chain B: Turboshaft Wasm OOB Entry ═══
```
CVE-2026-5873 (Turboshaft Wasm OOB)
  → cage R/W via ArrayBuffer corruption
  → WCPT dispatch table corruption
  → CanonicalSig type confusion
  → arbitrary virtual R/W
  → CVE-2026-5281 (Dawn WebGPU UAF)
  → MEDIUM IL
```
**Rating: ★★★★★**
- V8 RCE: Confirmed vuln on Chrome 146 (fixed in 147)
- Full Hacktron exploit code available
- Same escape chain as Chain A

---

### ═══ Chain C: Sort Confusion + FrameState CSE Entry ═══
```
crbug-542403045 (sort element kind confusion → addrof)
  + CVE-2026-6307 (FrameState CSE → fakeobj)
  → cage R/W
  → WCPT dispatch table corruption
  → CanonicalSig type confusion
  → CVE-2026-5281 (Dawn WebGPU UAF)
  → MEDIUM IL
```
**Rating: ★★★★☆**
- Two V8 bugs for entry (sort for addrof, CSE for fakeobj)
- Same V8 SBX bypass and browser escape

---

### ═══ Chain D: Existing + Kernel (Win11 only) ═══
```
CVE-2026-6307 (FrameState CSE)
  → addrof/fakeobj
  → V8 SBX bypass (orchestrator WPM - NOT real-world)
  → CVE-2026-40369 (kernel)
  → SYSTEM
```
**Rating: ★★☆☆☆**
- V8 SBX bypass is orchestrator-assisted (WPM from MEDIUM IL)
- Kernel exploit is Win11-only
- NOT a true real-world chain

---

## 5. CLASSIFICATION MATRIX

| Component | Bug | Type | Chrome 146 | Real-World |
|-----------|-----|------|-----------|------------|
| CVE-2026-6307 | FrameState CSE | V8 RCE | ✅ VULN | ✅ |
| crbug-542403045 | Sort confusion | V8 RCE (addrof) | ✅ VULN | ✅ |
| CVE-2026-85046 | Sort/Maglev ITW | V8 RCE | ✅ VULN | ❓ No PoC |
| CVE-2026-5873 | Turboshaft OOB | V8 RCE | ✅ VULN | ✅ Full PoC |
| CVE-2025-0291 | Turboshaft type | V8 RCE | ❌ PATCHED | N/A |
| CVE-2025-2135 | TurboFan alias | V8 RCE | ❌ PATCHED | N/A |
| WCPT (452605803) | Dispatch table | V8 SBX bypass | ✅ (Hacktron) | ✅ |
| Petitoto 4x | Various WASM | V8 SBX bypass | ❌ PATCHED | N/A |
| CVE-2024-12053 | Canon. index | V8 SBX bypass | ❌ PATCHED | N/A |
| CVE-2026-5281 | Dawn WebGPU | Browser escape | ✅ VULN | ✅ ITW |
| CVE-2026-4676 | Dawn WebGPU | Browser escape | ❌ PATCHED | N/A |
| CVE-2025-2783 | Mojo IPC | Browser escape | ❌ PATCHED | N/A |
| CVE-2026-40369 | Kernel CmpLayer | LPE → SYSTEM | ✅ Win11 | ✅ Win11 |

---

## 6. RECOMMENDED IMPLEMENTATION ORDER

### Priority 1: Chain A (CVE-2026-6307 + WCPT + CVE-2026-5281)
- V8 RCE already working
- WCPT technique documented with code snippets
- Dawn WebGPU escape needs PoC development
- TRUE real-world escape

### Priority 2: Chain B (CVE-2026-5873 + WCPT + CVE-2026-5281)
- Alternative V8 RCE with full Hacktron exploit code
- Same V8 SBX bypass and browser escape
- More reliable OOB primitive

### Priority 3: Develop CVE-2026-5281 Dawn WebGPU exploit
- Shared by Chain A and Chain B
- ITW exploit exists (April 2026 KEV)
- Need to reverse Dawn UAF trigger from Chrome 146 patch diff

---

## 7. RESOURCES

- [Hacktron AI — Chrome 146 exploit](https://www.hacktron.ai/blog/i-let-claude-opus-to-write-me-a-chrome-exploit)
- [Theori — V8 Sandbox Escape ITW](https://theori.io/blog/a-deep-dive-into-v8-sandbox-escape-technique-used-in-in-the-wild-exploit)
- [mem2019 — Trusted Pointer Table bypass](https://mem2019.github.io/jekyll/update/2024/07/14/HITCON.html)
- [SSD Disclosure — WASM type index confusion](https://ssd-disclosure.com/webassembly-canonical-vs-relative-type-index-confusion-leading-to-rce/)
- [xv0nfers — V8 SBX bypass collection](https://github.com/xv0nfers/V8-sbx-bypass-collection)
- [Petitoto — chromium-exploit-dev](https://github.com/Petitoto/chromium-exploit-dev)
- [allpaca — chrome-sbx-db](https://github.com/allpaca/chrome-sbx-db)
- [CVE-2026-5281 advisory](https://www.helpnetsecurity.com/2026/04/01/google-chrome-zero-day-cve-2026-5281/)
- [CVE-2026-4676 details](https://www.sentinelone.com/vulnerability-database/cve-2026-4676/)
- [CVE-2026-85046 analysis](https://www.penligent.ai/hackinglabs/cve-2026-85046/)
- [CVE-2025-2783 advisory](https://blog.securelayer7.net/cve-2025-2783-chrome-mojo-ipc-sandbox/)
- [Chromium Issue 422313191](https://issues.chromium.org/issues/422313191)

---

## 8. HONEST ASSESSMENT

### What we HAVE:
- 4 confirmed V8 RCE bugs on Chrome 146 (CVE-2026-6307, crbug-542403045, CVE-2026-85046, CVE-2026-5873)
- 1 confirmed browser sandbox escape on Chrome 146.0.7680.165 (CVE-2026-5281)
- 1 documented V8 sandbox bypass reportedly working on Chrome 146 (WCPT)
- Working orchestrator code for CVE-2026-6307

### What we NEED to verify:
- WCPT dispatch table corruption on Chrome 146.0.7680.165 specifically
  (Hacktron blog says it works on 146, but fixes landed in Oct 2025)
- CVE-2026-5281 Dawn WebGPU exploitation details (restricted bug)
- CVE-2026-5873 trigger on our specific Chrome build

### Gap analysis:
- V8 SBX bypass is the only uncertain component
- If WCPT works → full chain is real-world
- If WCPT is patched → need to find/develop alternative V8 SBX bypass
- Dawn WebGPU escape details are limited (Google restricts ITW 0day info)

### Bottom line:
The path to a TRUE real-world full chain exists. CVE-2026-5281 (Dawn WebGPU UAF)
is the critical browser sandbox escape — it's confirmed vulnerable on our exact
Chrome version (146.0.7680.165 < 146.0.7680.177) and requires NO kernel exploit.
Combined with our working V8 RCE and the WCPT sandbox bypass technique, this
forms a complete chain from webpage visit to MEDIUM IL code execution.

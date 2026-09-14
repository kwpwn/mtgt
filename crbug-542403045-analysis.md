# crbug-542403045 — Array.prototype.sort Element Kind Confusion

## Summary
**Type**: V8 JIT compiler type confusion (Maglev + TurboFan)
**Root cause**: `CanInlineArrayIteratingBuiltin` unions polymorphic receiver element kinds without verifying agreement before inlining `Array.prototype.sort()`
**Fix commit**: `e0562d87ad9c17042b581582c99237d798572e67` (Aug 7, 2026)
**Author**: Jakob Linke (jgruber@chromium.org)
**Affected**: Chrome ≤151 (V8 before refs/heads/main@{#109116})
**Target for exploit**: Chrome 146.0.7680.165 (V8 14.6.202.26) — CONFIRMED VULNERABLE

## Root Cause

```
IteratingArrayBuiltinHelper (js-call-reducer.cc / maglev-graph-builder.cc)
  → unions element kinds from polymorphic feedback
  → {PACKED_SMI_ELEMENTS, PACKED_ELEMENTS} → union = PACKED_ELEMENTS
  → inlines Array.prototype.sort with PACKED_ELEMENTS access

Inlined sort:
  1. Snapshot elements (reads as PACKED_ELEMENTS → tagged HeapObject pointers)
  2. Runs comparefn — which does a.fill(0) → transitions to PACKED_SMI_ELEMENTS
  3. Map check passes (PACKED_SMI map existed in original polymorphic set)
  4. Copies snapshot back → writes HeapObject tagged pointers into PACKED_SMI array
     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     TYPE VIOLATION: Smi array now contains HeapObject pointers
```

## Fix (2 files)

**js-call-reducer.cc** (TurboFan):
```cpp
// NEW: check all maps agree on element kind
if (!h.all_elements_kinds_equal()) return h.inference()->NoChange();
```

**maglev-graph-builder.cc** (Maglev):
```cpp
if (std::any_of(possible_maps->begin(), possible_maps->end(),
    [&](compiler::MapRef map) {
      return map.elements_kind() != elements_kind;
    })) {
  FAIL(" to reduce Array.prototype.sort - receiver elements kinds disagree");
}
```

## Exploitation Analysis

### addrof — CONFIRMED
```
Corrupted array: Map=PACKED_SMI_ELEMENTS, FixedArray=[HeapObj_ptr0, HeapObj_ptr1]

JIT read (PACKED_SMI path):
  tagged_value = load(elements + index * 4 + 8)
  result = tagged_value >> 1  (arithmetic shift, Smi decode)
  → returns (cage_offset | 1) >> 1 as a JS number

Recovery: cage_offset = (result * 2 + 1) >>> 0
  or: cage_offset = (result << 1) | 1  (for 32-bit compressed ptr)
```

### fakeobj — NOT directly achievable
```
Writing to PACKED_SMI array: stores value << 1 (Smi encode)
  → bit 0 is ALWAYS 0 (Smi tag)
  → can never create HeapObject-tagged value (bit 0 = 1) through Smi write
  → one-directional confusion only (HeapObj→Smi, not Smi→HeapObj)

Fundamental asymmetry:
  - HeapObject ptr in Smi array = TYPE VIOLATION (exploitable → addrof)
  - Smi value in PACKED array = VALID (Smis are subset of PACKED_ELEMENTS)
```

### Recommended full chain approach
1. addrof via sort element kind confusion
2. fakeobj via CVE-2026-6307 FrameState CSE (same Chrome 146 version)
   OR: OOB write via sort + comparefn FixedArray shrink (speculative, needs testing)
3. V8 sandbox bypass via WASM JIT hijack
4. Browser sandbox escape (kernel or Mojo)

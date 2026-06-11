# Blind the Watchers — Building a Physical-Memory EDR Bypass from Scratch

> **Target:** Windows 11 22H2 / 23H2, AMD Ryzen system  
> **Driver primitive:** AMDRyzenMasterDriverV20 — arbitrary physical read/write via IOCTL  
> **Goal:** Disable WdFilter (Windows Defender) + Huorong (火绒) kernel callbacks without loading a custom driver or requiring PDB symbols  

---

## Background

The AMD Ryzen Master driver (`AMDRyzenMasterDriverV20.sys`) exposes two IOCTLs:

```
IOCTL_PHYS_READ  0x81112F08  — read N bytes from physical address
IOCTL_PHYS_WRITE 0x81112F0C  — write N bytes to physical address
```

With these two primitives and Administrator rights, you can read and write any location in physical RAM — including live kernel data structures. No shellcode injection, no kernel driver signing bypass needed. The plan was simple in theory: scan physical memory to find EDR callback registrations and zero them out.

In practice, every step had a surprise.

---

## Step 0 — The Three Original Tools

Before `all_edr_bypass.c` existed there were three separate tools:

- **notify_callbacks_bypass.c** — zero PspCreate/Load/Thread notify arrays
- **flt_bypass_global.c** — patch minifilter PreOperation callbacks to `xor eax,eax; ret`
- **etw_ti_bypass.c** — patch EtwTiLog\* prologues or zero the IsEnabled provider field

Each worked standalone. The plan was to merge them into one binary, add CM callback and WFP callout support, and clean up the heuristics.

---

## Step 1 — Ps\* Notify Arrays: The Callee Problem

The notify arrays (`PspCreateProcessNotifyRoutine` etc.) live in ntoskrnl's `.data` section. The original approach: scan the setter function (`PsSetCreateProcessNotifyRoutine`) for a RIP-relative `LEA` instruction pointing into the data section, validate by reading the array content.

On Windows 10 this worked. On Windows 11 22H2+ it silently returned NOT FOUND.

The setter is now a thin wrapper:

```asm
PsSetCreateProcessNotifyRoutine:
    test rdx, rdx
    jz   short stub
    call PspSetCreateProcessNotifyRoutineEx2   ; <── LEA is in HERE
    ...
```

The LEA instruction pointing to `PspCreateProcessNotifyRoutine` lives inside the callee, not the exported setter. The fix was to follow all `E8`/`E9` (CALL/JMP rel32) instructions within the first 512 bytes of the setter, build a scan list of up to 8 functions, and search all of them.

At the same time the `rva_in_data_section()` check was dropped — it rejected pages whose section flags didn't exactly match "writable non-executable", which happened silently on this build. The array content validation (all 64 slots are either zero or a canonical kernel VA) is discriminating enough on its own.

**Second surprise:** `PspLoadImageNotifyRoutine` and `PspCreateThreadNotifyRoutine` returned the *same* physical address. The score-based selection algorithm found the same LEA as the best match for both. The fix: accumulate found VAs and pass them as exclusions to each subsequent search, forcing each array to get a unique address.

---

## Step 2 — ObRegisterCallbacks: The BSOD

With the four scan passes running (OB, FLT, CM, WFP), applied the bypass, ran `test_bypass.exe` — BSOD.

The crash came from `ob_apply_edr` and `cm_apply_edr` zeroing callback entries attributed to `usbhub.sys`, `win32k.sys`, `e1i68x64.sys` (Intel NIC), `partmgr.sys`, and a dozen other Windows system drivers.

These drivers aren't EDR — but the scan had found pool allocations that *looked* like OB callback entries, with function pointers landing inside those drivers' code. The whitelist in `classify_driver()` was too narrow. Any driver not explicitly listed became `DRV_OTHER` and got targeted.

Zeroing a random function pointer inside what the OS thought was a `KDPC` or `IO_WORKITEM` — not an OB callback — corrupted that structure. Next time the kernel used it: blue screen.

The fix was a layered targeting gate `is_edr_target()`:

1. Explicitly known EDR products in `g_edr_list[]` → always target (catches WdFilter, hrdevmon, hrwfpdrv and variants)
2. `hr*.sys` wildcard → all Huorong drivers regardless of name
3. `classify_driver() != DRV_OTHER` → skip (already in explicit system/network/VM whitelist)
4. `is_microsoft_driver()` — publisher check with per-name cache → skip Microsoft OS components
5. `is_hw_vendor()` — Intel, NVIDIA, AMD, Realtek, Broadcom etc. → skip
6. Pattern skip: `dump_*`, `AMDRyzen*`, `vm3d*`, `mcupdate_*`, `Basic*.sys` → no version info, definitely not AV
7. Final gate: `get_driver_company()` returns NULL → conservative skip (real AV products always embed version info)

After this, the BSOD went away. Huorong and WdFilter still targeted. Intel NIC, USB hub, kernel graphics subsystem untouched.

---

## Step 3 — WFP Callouts: 33 False Positives

WFP callout scan found 33 "EDR callouts" attributed to `WdFilter.sys`. WdFilter is a minifilter, not a WFP driver. Something was wrong.

The `_FWPS_CALLOUT` structure looks like:

```
+0x00  LIST_ENTRY  (Flink, Blink)
+0x10  GUID        calloutKey
+0x20  UINT32      flags
+0x24  UINT32      calloutId        ← Guard 4
+0x28  PVOID       classifyFn       ← anchor
+0x30  PVOID       notifyFn
+0x38  PVOID       flowDeleteFn     ← Guard 6 (new)
+0x40  PVOID       context          ← Guard 7 (new)
```

WdFilter's minifilter callback tables — `_CALLBACK_NODE` and similar — also have doubly-linked lists and function pointers. Some of them were passing all 5 original guards and getting counted as WFP callouts.

Three additional guards were added:

- **Guard 6:** `flowDeleteFn` at off+0x10 must be NULL or point into the same driver. WdFilter pool nodes usually have a random pointer there.
- **Guard 7:** `context` at off+0x18 must be NULL or a canonical kernel VA (bits 63:48 == 0xFFFF). Non-VA integers fail this.
- **Guard 4 tightened:** `calloutId` capped at 0xFFFF. FWP assigns sequential IDs; values above 65535 don't occur on real systems.

Also: `wfp_try()` now rejects any `classifyFn` not in a `DRV_OTHER` driver — system/network/VM drivers either have legitimate WFP callouts (skip) or produce false positives (also skip).

Result: 33 false positives → 1 real EDR callout.

---

## Step 4 — OB: Pointer Zeroing → Enabled Flag Toggle

The original approach zeroed the `PreOperation` and `PostOperation` pointers in `OB_CALLBACK_ENTRY`. This works but has a subtle race: if the EDR's dispatch function is executing on another CPU at the moment the pointer is zeroed, it could dereference NULL.

EDRSandblast uses a cleaner technique: clear the `Enabled` BOOL at `struct+0x14`. The kernel checks this flag before ever touching the function pointers:

```c
if (!entry->Enabled) return; // kernel internally, before dispatching
```

It's a 4-byte atomic write. The callback is suppressed without touching any pointer.

Implementation required storing `enabled_pa = cpa + off - 0x14` per entry during scan. The anc=0x20 layout (an older OB_CALLBACK_ENTRY variant) has Enabled at a different offset (`off - 0x0C`), which was handled by extracting `ob_try_20()` as a separate function.

The fallback for entries where `enabled_pa` fails validation: zero the PreOperation pointer (original approach).

---

## Step 5 — Minifilter: Code Patch → List Unlink

Patching the PreOperation function prologue to `xor eax,eax; ret` works but leaves a visible artifact: the live memory bytes differ from the on-disk image. Any integrity checker will flag it.

EDRSandblast's approach is cleaner: unlink the callback node from the Filter Manager's per-IRP doubly-linked list. The kernel traverses the list for each file operation; if the node isn't in the list, the callback never fires. No code modification.

```
Before:  PREV ←→ EDR_NODE ←→ NEXT
After:   PREV ←→           ←→ NEXT   (EDR_NODE skipped)
```

The unlink requires writing to `PREV.Flink` and `NEXT.Blink`. These are kernel virtual addresses — we know them from the scan (raw64[0..7] and raw64[8..15] of each FltNode). To write to them via physical address, we need VA→PA translation.

Which means we need the kernel's CR3.

---

## Step 6 — Finding CR3: Two Surprises

### Surprise 1: PML4 Self-Reference at 0x1ED is Optional

The standard Windows trick: the PML4 has a self-referencing entry at index 0x1ED. Scanning 4KB-page candidates for `PML4[0x1ED] & frame_mask == page_base` finds CR3.

On Windows 11 22H2+, this entry is at a *random* index chosen at boot (KASLR for the PML4 self-reference). The fixed-index scan found nothing.

Fix: Pass 2 reads the full 4KB page and checks all 512 entries:

```c
for(int idx=0x100; idx<0x200; idx++){   // kernel-half only
    uint64_t e = *(uint64_t*)(pg + idx*8);
    if((e & 1) && (e & frame_mask) == pa) return pa;
}
```

### Surprise 2: Hyper-V VMs Have Two PML4s

On Hyper-V guest VMs, this scan found a CR3 at `0x3E000` — which had a self-referencing entry and passed validation. But `va_to_pa(pool_address)` returned 0 for every kernel pool VA.

The CR3 at `0x3E000` is the hypervisor's own PML4, not the Windows guest kernel's PML4. The hypervisor maps its own memory correctly (hence the self-reference validates) but doesn't map the guest kernel's non-paged pool. The real guest CR3 lives in a layer that isn't directly visible through the guest's physical address space.

Result: on Hyper-V, va_to_pa fails, list-unlink falls back to code-patch. On bare metal, both work.

---

## Step 7 — ETW-TI: The Wall

Method A: patch `EtwTiLog*` function prologues. On Windows 11 22H2+ these functions are no longer exported. `pe_export_rva()` returns 0 for all of them. Method A unavailable.

Method B: scan physical memory for the ETW-TI provider GUID (`{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}`), find the `_ETW_GUID_ENTRY`, zero its `IsEnabled` field. On some Windows 11 builds, the GUID isn't found — either the provider structure has moved or its layout changed enough to break the heuristic field validation.

This remains an open problem. The proper approach (used by EDRSandblast) resolves `EtwThreatIntProvRegHandle` via PDB symbols and follows the `_ETW_REG_ENTRY → GuidEntry → ProviderEnableInfo` chain. Without PDB access, this is hard to do portably.

Current status: ETW-TI bypass silently skips on newer builds. NtReadVirtualMemory generates telemetry but the LSASS dump still completes — the OB and minifilter bypasses are sufficient for the primary use case.

---

## Step 8 — Performance: From Minutes to Seconds

With four separate full-RAM passes (OB scan, FLT scan, CM scan, WFP scan), scanning 6 GB took several minutes on the test VM. Each pass was:

```
6 GB / 64 KB chunks = 98,304 IOCTL calls per pass
4 passes × 98,304 = 393,216 IOCTL calls total
```

At roughly 1 ms overhead per IOCTL: ~6.5 minutes. Not usable.

Three changes collapsed this to seconds:

**1. Single combined pass.** `combined_pool_scan()` reads each chunk once and runs all four scanners on the same data. 4× fewer IOCTL calls immediately.

**2. Larger chunks.** CHUNK_SZ 64 KB → 256 KB. Fewer round-trips to the driver. Pre-allocated static output buffer eliminates per-call malloc/free.

**3. Kernel-VA pre-filter.** Every scanner requires a kernel function pointer (bits 63:48 == 0xFFFF) at the candidate offset. A single byte check:

```c
if(g_chunk[off + 7] != 0xFF) continue;
```

rejects ~95% of all 8-byte positions before calling any scanner. The inner loop does almost no work on uninteresting memory.

Result: ~60-80× speedup. 6 GB scanned in 5-10 seconds.

---

## Step 9 — Verify Count Was Always Wrong

After restore, the verify loop reported `25/35 entries verified`. Ten entries always failed. The cause was subtle.

OB entries using the Enabled flag store a 4-byte original value in `orig_en[4]`. The verify snapshot put this into a `uint64_t orig` field (upper 32 bits = 0). After restore, reading 8 bytes from `enabled_pa` returned the 4-byte Enabled value *plus* the 4 bytes immediately following it in memory (some other field). `cur != orig` because the upper bytes didn't match the zero-padded snapshot.

Fix: `VSnap.sz` field. The snapshot records whether it covers 4 or 8 bytes. Verify reads exactly `sz` bytes and compares with a mask:

```c
uint64_t mask = (sz >= 8) ? ~0ULL : ((1ULL << (sz * 8)) - 1);
if((cur & mask) == (orig & mask)) v_ok++;
```

After the fix: `35/35 entries verified`.

---

## Final Architecture

```
all_edr_bypass.exe
│
├── Phase 1: SCAN (read-only)
│   ├── [1/6] Ps* arrays — LEA scan + callee follow
│   ├── [2/6] combined_pool_scan — 1 pass, 256KB chunks
│   │         ├── OB  — ob_try (anc=0x28) + ob_try_20 (anc=0x20)
│   │         ├── FLT — flt_try (anc ∈ {0x20,0x18,0x28})
│   │         ├── CM  — cm_try (with altitude) + cm_try_noalt (no altitude)
│   │         └── WFP — wfp_try (7 guards)
│   ├── [3/6] ETW-TI export check
│   └── [4/6] Watchdog — IAT scan for re-registration call sites
│
├── Phase 2: CONFIRM
│   └── Summary + Proceed? [y/N]
│
└── Phase 3: APPLY
    ├── [1/7] Watchdog Kill   — patch IAT CALL → xor rax,rax; nop×3
    ├── [2/7] Ps* arrays      — zero each live slot
    ├── [3/7] OB callbacks    — clear Enabled flag (EDRSandblast tech 1)
    │                           fallback: zero PreOp pointer
    ├── [4/7] Minifilter      — LIST_ENTRY unlink via va_to_pa
    │                           fallback: patch PreOp → xor eax,eax; ret
    ├── [5/7] ETW-TI          — Method A (exports) / Method B (GUID scan)
    ├── [6/7] CM callbacks    — zero Function pointer
    └── [7/7] WFP callouts    — zero classifyFn + notifyFn
```

---

## Verification

```
test_bypass.exe  (run while all_edr_bypass holds the bypass)

[1] Ps* Notify   CreateProcess(whoami) exits normally
[2] OB           OpenProcess(LSASS, ALL_ACCESS) succeeds
[3] ETW-TI       ReadProcessMemory(LSASS) succeeds
[4] Minifilter   PE file written to disk, survives 800 ms
[5] CM           RegSetValueEx to test key succeeds
[6] GOLD         MiniDumpWriteDump(LSASS) → ~55 MB, auto-deleted
```

Test [6] is definitive. A 55 MB LSASS dump requires the entire chain: OB bypass to open the handle, minifilter bypass to write the file, the process not being terminated by any remaining callback. If it produces real data, the bypass is working.

---

## Open Problems

| Problem | Status |
|---|---|
| ETW-TI on Win11 22H2+ | Needs PDB-derived `EtwThreatIntProvRegHandle` offset |
| Minifilter list-unlink on Hyper-V | va_to_pa finds hypervisor PML4, not guest PML4 |
| Watchdog: 0 IAT sites found | EDR uses direct calls or different re-registration mechanism |
| WFP: hrwfpdrv sometimes not found | CM callbacks zeroed instead (also blocks Huorong registry monitoring) |

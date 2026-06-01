# Connor McGarr Study Track

This branch collects deep-research notes in English based on Connor McGarr's Windows internals / Windows exploit series.

## Files

- `CONNOR_MCGARR_WINDOWS_KERNEL_DEEP_RESEARCH.md`: master map connecting the articles under a modern exploit-thinking framework.
- `01_PAGING_AND_PTE_DEEP_DIVE.md`: dedicated deep dive on paging, PTE, VA->PA, and SMEP/NX/HVCI implications.
- `02_SMEP_NX_PTE_BYPASS_CONCEPTS.md`: SMEP/NX/PTE bypass thinking and why HVCI changes the required mental model.
- `04_POOL_EXPLOITATION_KLFH_SEGMENT_HEAP.md`: pool exploitation, kLFH, grooming, OOB read/write, and object selection.
- `06_CFG_XFG_KCFG_CET_CONTROL_FLOW.md`: forward-edge vs backward-edge CFI, CFG/XFG/kCFG/CET.
- `07_HVCI_EXISTING_CODE_INVOCATION.md`: HVCI, existing-code invocation, dummy thread/KTHREAD/ROP concepts, and mitigation pressure.

## Sources

- https://connormcgarr.github.io/paging/
- https://connormcgarr.github.io/x64-Kernel-Shellcode-Revisited-and-SMEP-Bypass/
- https://connormcgarr.github.io/Kernel-Exploitation-2/
- https://connormcgarr.github.io/examining-xfg/
- https://connormcgarr.github.io/swimming-in-the-kernel-pool-part-1/
- https://connormcgarr.github.io/swimming-in-the-kernel-pool-part-2/
- https://connormcgarr.github.io/kuser-shared-data-changes-win-11/
- https://connormcgarr.github.io/hvci/

## Next splits

- `03_WRITE_WHAT_WHERE_TARGET_SELECTION.md`
- `05_KUSER_SHARED_DATA_MAPPING_CHANGES.md`

# Connor McGarr Study Track

Nhanh nay gom cac ghi chu deep-research tieng Viet dua tren cac bai Windows internals / Windows exploit cua Connor McGarr.

## Files

- `CONNOR_MCGARR_WINDOWS_KERNEL_DEEP_RESEARCH_VI.md`: master map noi cac bai voi nhau theo exploit-thinking hien dai.
- `01_PAGING_AND_PTE_DEEP_DIVE.md`: deep dive rieng ve paging, PTE, VA->PA, SMEP/NX/HVCI lien quan.
- `02_SMEP_NX_PTE_BYPASS_CONCEPTS.md`: SMEP/NX/PTE bypass thinking va vi sao HVCI doi mental model.
- `04_POOL_EXPLOITATION_KLFH_SEGMENT_HEAP.md`: pool exploitation, kLFH, grooming, OOB read/write, object selection.
- `06_CFG_XFG_KCFG_CET_CONTROL_FLOW.md`: forward-edge vs backward-edge CFI, CFG/XFG/kCFG/CET.
- `07_HVCI_EXISTING_CODE_INVOCATION.md`: HVCI, existing-code invocation, dummy thread/KTHREAD/ROP concept va mitigation pressure.

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

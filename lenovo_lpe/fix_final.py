"""
fix_final.py  —  Final BSOD prevention pass for all exploit files.

Root cause: MmMapIoSpace() inside LnvMSRIO.sys leaks a kernel resource
per call.  Files that scan all of [1MB, 3GB) page-by-page make ~800 K
calls and exhaust the resource → 0x3B BSOD.

Strategy:
  • ALL physical scans in this codebase search for the System EPROCESS
    (PID=4), which is always loaded within the first 128 MB of RAM.
  • Cap the fallback scan range at [1 MB, 128 MB).
    Worst-case reads: 127 chunks × 256 pages = 32 512 — proven safe.
  • Files 02 and 03 already use APL walk for non-System targets; their
    FindEprocess is now called only once for PID=4.
  • Files 04-13 use GetSystemCR3 (early-exit loop) then VA→PA + APL walk.
    The single scan loop exits after ~4-8 chunks (4-16 MB) in practice.

This script replaces the 3 GB fallback size with 128 MB in every .cpp.
"""
import os, re

BASE = r"E:\driver_research\lenovo_lpe"

OLD = '        ranges[0].size = 0xBFF00000;  // [1 MB, 3 GB) \xe2\x80\x94 safe on all x86/VMware systems'

# Build exact old string as it appears in files (ASCII, written by fix_fallback2.py)
OLD_BYTES = "        ranges[0].size = 0xBFF00000;  // [1 MB, 3 GB) — safe on all x86/VMware systems"
NEW_BYTES = "        ranges[0].size = 0x07F00000;  // [1 MB, 128 MB) — System EPROCESS always here"

# Also handle the ph_ranges variant (file 01)
OLD_PH = "        ph_ranges[0].size = 0xBFF00000;  // [1 MB, 3 GB) — safe on all x86/VMware systems"
NEW_PH = "        ph_ranges[0].size = 0x07F00000;  // [1 MB, 128 MB) — System EPROCESS always here"

total = 0
for fn in sorted(os.listdir(BASE)):
    if not fn.endswith(".cpp"):
        continue
    path = os.path.join(BASE, fn)
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        src = f.read()

    out = src
    hits = []

    if OLD_BYTES in out:
        cnt = out.count(OLD_BYTES)
        out = out.replace(OLD_BYTES, NEW_BYTES)
        hits.append(f"ranges ×{cnt}")

    if OLD_PH in out:
        cnt = out.count(OLD_PH)
        out = out.replace(OLD_PH, NEW_PH)
        hits.append(f"ph_ranges ×{cnt}")

    if out != src:
        with open(path, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"[+] {fn}: {', '.join(hits)}")
        total += 1
    else:
        print(f"    {fn}: nothing to patch")

print(f"\nPatched {total} file(s). Fallback is now [1 MB, 128 MB).")

"""
fix_fallback.py  —  patch GetPhysRanges fallback in all exploit .cpp files

Problem: fallback used `ms.ullTotalPhys` as the scan upper bound.
On a 4GB VMware VM, ullTotalPhys ≈ 3.7 GB which is ABOVE the 3GB-4GB MMIO hole
→ MmMapIoSpace() on those addresses causes 0x3B BSOD.

Fix: cap first range at 3 GB (0xC0000000), add a second range at 4 GB+ if needed.
"""
import os

BASE = r"E:\driver_research\lenovo_lpe"

# ── replacement body (no const to avoid redefinition in files with 2 fallbacks) ──
SAFE_BODY_N = """\
        ranges[0].base = 0x100000;
        ranges[0].size = (ms.ullTotalPhys < 0xC0000000ULL ? ms.ullTotalPhys : 0xC0000000ULL) - 0x100000;
        n = 1;
        if (ms.ullTotalPhys > 0xC0000000ULL) {
            ranges[1].base = 0x100000000ULL;
            ranges[1].size = ms.ullTotalPhys - 0xC0000000ULL;
            n++;
        }"""

SAFE_BODY_NR = """\
        ranges[0].base = 0x100000;
        ranges[0].size = (ms.ullTotalPhys < 0xC0000000ULL ? ms.ullTotalPhys : 0xC0000000ULL) - 0x100000;
        n_ranges = 1;
        if (ms.ullTotalPhys > 0xC0000000ULL) {
            ranges[1].base = 0x100000000ULL;
            ranges[1].size = ms.ullTotalPhys - 0xC0000000ULL;
            n_ranges = 2;
        }"""

SAFE_BODY_NR_PH = """\
        ph_ranges[0].base = 0x100000;
        ph_ranges[0].size = (ms2.ullTotalPhys < 0xC0000000ULL ? ms2.ullTotalPhys : 0xC0000000ULL) - 0x100000;
        n_ranges = 1;
        if (ms2.ullTotalPhys > 0xC0000000ULL) {
            ph_ranges[1].base = 0x100000000ULL;
            ph_ranges[1].size = ms2.ullTotalPhys - 0xC0000000ULL;
            n_ranges = 2;
        }"""

# ── patterns to replace ────────────────────────────────────────────────────────

# files 04-13: GetSystemCR3, uses n + ranges (multiline)
OLD_N = "        ranges[0].base = 0x100000;\n        ranges[0].size = ms.ullTotalPhys;\n        n = 1;"

# files 02, 03: FindEprocess, uses n_ranges + ranges (single line)
OLD_NR_ONELINER = "        ranges[0].base = 0x100000; ranges[0].size = ms.ullTotalPhys; n_ranges = 1;"

# file 01: main, uses n_ranges + ph_ranges + ms2 (multiline)
OLD_NR_PH = "        ph_ranges[0].base = 0x100000;\n        ph_ranges[0].size = ms2.ullTotalPhys;\n        n_ranges = 1;"

total_patched = 0

for fn in sorted(os.listdir(BASE)):
    if not fn.endswith(".cpp"):
        continue
    path = os.path.join(BASE, fn)
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        src = f.read()

    out = src
    hits = []

    if OLD_N in out:
        cnt = out.count(OLD_N)
        out = out.replace(OLD_N, SAFE_BODY_N)
        hits.append(f"n-fallback ×{cnt}")

    if OLD_NR_ONELINER in out:
        cnt = out.count(OLD_NR_ONELINER)
        out = out.replace(OLD_NR_ONELINER, SAFE_BODY_NR)
        hits.append(f"n_ranges-oneliner ×{cnt}")

    if OLD_NR_PH in out:
        cnt = out.count(OLD_NR_PH)
        out = out.replace(OLD_NR_PH, SAFE_BODY_NR_PH)
        hits.append(f"ph_ranges-fallback ×{cnt}")

    if out != src:
        with open(path, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"[+] {fn}: {', '.join(hits)}")
        total_patched += 1
    else:
        print(f"    {fn}: nothing matched")

print(f"\nPatched {total_patched} file(s).")

"""
fix_fallback2.py  —  simplify fallback to hardcoded [1MB, 3GB) only

Previous fix added a range[1] above 4GB whose size was computed as
    ullTotalPhys - 3GB
but ullTotalPhys is the TOTAL usable RAM (sum of segments), NOT the
highest physical address.  On a 6GB VMware VM, that puts range[1] end
at 4GB + (6207MB - 3072MB) = 7.07GB, past the actual RAM ceiling of
~6.5GB → MmMapIoSpace on a non-existent PA → BSOD.

Safe approach: fallback = [1MB, 3GB) hardcoded.
Kernel (ntoskrnl), System EPROCESS, and almost all process EPROCESS
blocks are always in the first 3GB of physical RAM.
"""
import os

BASE = r"E:\driver_research\lenovo_lpe"

# ── replace these multi-line blocks ──────────────────────────────────────────

OLD_N = """\
        ranges[0].base = 0x100000;
        ranges[0].size = (ms.ullTotalPhys < 0xC0000000ULL ? ms.ullTotalPhys : 0xC0000000ULL) - 0x100000;
        n = 1;
        if (ms.ullTotalPhys > 0xC0000000ULL) {
            ranges[1].base = 0x100000000ULL;
            ranges[1].size = ms.ullTotalPhys - 0xC0000000ULL;
            n++;
        }"""

NEW_N = """\
        ranges[0].base = 0x100000;
        ranges[0].size = 0xBFF00000;  // [1 MB, 3 GB) — safe on all x86/VMware systems
        n = 1;"""

OLD_NR = """\
        ranges[0].base = 0x100000;
        ranges[0].size = (ms.ullTotalPhys < 0xC0000000ULL ? ms.ullTotalPhys : 0xC0000000ULL) - 0x100000;
        n_ranges = 1;
        if (ms.ullTotalPhys > 0xC0000000ULL) {
            ranges[1].base = 0x100000000ULL;
            ranges[1].size = ms.ullTotalPhys - 0xC0000000ULL;
            n_ranges = 2;
        }"""

NEW_NR = """\
        ranges[0].base = 0x100000;
        ranges[0].size = 0xBFF00000;  // [1 MB, 3 GB) — safe on all x86/VMware systems
        n_ranges = 1;"""

OLD_PH = """\
        ph_ranges[0].base = 0x100000;
        ph_ranges[0].size = (ms2.ullTotalPhys < 0xC0000000ULL ? ms2.ullTotalPhys : 0xC0000000ULL) - 0x100000;
        n_ranges = 1;
        if (ms2.ullTotalPhys > 0xC0000000ULL) {
            ph_ranges[1].base = 0x100000000ULL;
            ph_ranges[1].size = ms2.ullTotalPhys - 0xC0000000ULL;
            n_ranges = 2;
        }"""

NEW_PH = """\
        ph_ranges[0].base = 0x100000;
        ph_ranges[0].size = 0xBFF00000;  // [1 MB, 3 GB) — safe on all x86/VMware systems
        n_ranges = 1;"""

total = 0
for fn in sorted(os.listdir(BASE)):
    if not fn.endswith(".cpp"):
        continue
    path = os.path.join(BASE, fn)
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        src = f.read()

    out = src
    hits = []

    for old, new, tag in [(OLD_N, NEW_N, "n"), (OLD_NR, NEW_NR, "n_ranges"),
                           (OLD_PH, NEW_PH, "ph_ranges")]:
        if old in out:
            cnt = out.count(old)
            out = out.replace(old, new)
            hits.append(f"{tag} ×{cnt}")

    if out != src:
        with open(path, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"[+] {fn}: {', '.join(hits)}")
        total += 1
    else:
        print(f"    {fn}: nothing matched")

print(f"\nSimplified fallback in {total} file(s).")

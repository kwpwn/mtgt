#!/usr/bin/env python3
"""Targeted sysdiag analysis: watchdog, minifilter altitude, EPROCESS offsets used."""
import struct, re, pefile

path = r"E:\driver_research\amd_ryzen_master\sysdiag.sys"
with open(path, 'rb') as f:
    data = f.read()
pe = pefile.PE(data=data)

print("=== sysdiag.sys: Minifilter altitude strings ===")
# Search for altitude - UTF16 digits (5-6 chars)
for m in re.finditer(rb'(?:[\x30-\x39]\x00){5,6}', data):
    s = m.group().decode('utf-16-le', 'replace')
    if s.isdigit():
        off = m.start()
        print(f"  @{off:#08x}: UTF16 '{s}'")
# ASCII altitude
for m in re.finditer(rb'[0-9]{5,6}', data):
    val = int(m.group())
    if 100000 <= val <= 499999:  # typical minifilter range
        off = m.start()
        # Context
        ctx = data[max(0,off-4):off+12]
        asc = ''.join(chr(b) if 0x20<=b<=0x7e else '.' for b in ctx)
        print(f"  @{off:#08x}: ASCII '{m.group().decode()}' ctx={asc!r}")

print("\n=== sysdiag.sys: EPROCESS offset usage (specific dwords) ===")
# Known important offsets
target_offsets = {
    0x87C: "Protection (W10 21H2 x64)",
    0x878: "SignatureLevel (W10 21H2 x64)",
    0x87A: "SectionSignatureLevel (W10 21H2 x64)",
    0x884: "Protection (W11 22H2 x64)",
    0x880: "SignatureLevel (W11 22H2 x64)",
    0x882: "SectionSignatureLevel (W11 22H2 x64)",
    0x440: "UniqueProcessId (W10 21H2)",
    0x448: "ActiveProcessLinks (W10 21H2)",
    0x5A8: "ImageFileName (W10 21H2)",
    0x450: "UniqueProcessId (W11 22H2)",
    0x540: "ActiveProcessLinks (W11 22H2)",
    0x5B0: "ImageFileName (W11 22H2)",
}
# Search in .text section for these as immediate values in instructions
# MOV reg, [rax + 0x87C] would encode as: offset bytes in instruction stream
for s in pe.sections:
    sname = s.Name.rstrip(b'\x00').decode('ascii','replace')
    if '.text' in sname:
        sec = data[s.PointerToRawData:s.PointerToRawData+s.SizeOfRawData]
        fbase = s.PointerToRawData
        for target, name in target_offsets.items():
            # Search for 4-byte little-endian representation
            packed = struct.pack('<I', target)
            for m in re.finditer(re.escape(packed), sec):
                off = fbase + m.start()
                # Get surrounding bytes (instruction context)
                ctx = data[max(0,off-8):off+8].hex()
                print(f"  @{off:#08x}: {target:#06x} ({name}) ctx={ctx}")
        # Also search for 2-byte (for WORD-size offsets like 0x87C)
        for target, name in target_offsets.items():
            if target <= 0xFFFF:
                packed2 = struct.pack('<H', target)
                for m in re.finditer(re.escape(packed2), sec):
                    off = fbase + m.start()
                    ctx = data[max(0,off-6):off+6].hex()
                    print(f"  @{off:#08x}: WORD {target:#06x} ({name}) ctx={ctx}")

print("\n=== sysdiag.sys: Trampoline/hook mechanism (HR::DTrampo) ===")
# Look for trampoline-related strings
for pat in [b'TrampoLib', b'Trampo', b'DTrampo', b'hook', b'Hook', b'inline', b'Inline',
            b'JMP', b'jmp', b'patch', b'Patch']:
    for m in re.finditer(pat, data):
        off = m.start()
        ctx_start = max(0, off-20)
        ctx = ''.join(chr(data[i]) if 0x20<=data[i]<=0x7e else '.' for i in range(ctx_start, off+len(pat)+20))
        print(f"  [{pat.decode()}] @{off:#08x}: {ctx}")
    # Wide
    wide = b'\x00'.join(bytes([c]) for c in pat) + b'\x00'
    for m in re.finditer(re.escape(wide), data):
        off = m.start()
        # Decode wider context
        try:
            ctx_raw = data[max(0,off-20):off+len(wide)+40]
            ctx = ctx_raw.decode('utf-16-le', 'replace').replace('\x00','')[:60]
        except:
            ctx = ""
        print(f"  [W {pat.decode()}] @{off:#08x}: {ctx!r}")

print("\n=== sysdiag.sys: PAGE section strings ===")
for s in pe.sections:
    sname = s.Name.rstrip(b'\x00').decode('ascii','replace')
    if 'PAGE' in sname:
        sec = data[s.PointerToRawData:s.PointerToRawData+s.SizeOfRawData]
        fbase = s.PointerToRawData
        for m in re.finditer(rb'[\x20-\x7e]{8,}', sec):
            print(f"  @{fbase+m.start():#08x}: {m.group().decode()}")
        for m in re.finditer(rb'(?:[\x20-\x7e]\x00){8,}', sec):
            s2 = m.group().decode('utf-16-le','replace')
            print(f"  [W] @{fbase+m.start():#08x}: {s2}")

pe.close()
print("\nDONE.")

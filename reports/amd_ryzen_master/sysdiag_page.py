#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sysdiag PAGE section + minifilter altitude + TrampoLib."""
import sys, struct, re, pefile
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

path = r"E:\driver_research\amd_ryzen_master\sysdiag.sys"
with open(path, 'rb') as f:
    data = f.read()
pe = pefile.PE(data=data)

print("=== sysdiag.sys: Minifilter altitude (UTF16 candidates in .rdata) ===")
for s in pe.sections:
    sname = s.Name.rstrip(b'\x00').decode('ascii','replace')
    if sname in ['.rdata', '.data']:
        sec = data[s.PointerToRawData:s.PointerToRawData+s.SizeOfRawData]
        fbase = s.PointerToRawData
        # UTF16 digit sequences
        for m in re.finditer(rb'(?:[\x30-\x39]\x00){4,7}', sec):
            s2 = m.group().decode('utf-16-le','replace')
            if s2.isdigit() and 10000 <= int(s2) <= 499999:
                print(f"  [{sname}] @{fbase+m.start():#08x}: '{s2}'")

print("\n=== sysdiag.sys: TrampoLib references ===")
for m in re.finditer(rb'T\x00r\x00a\x00m\x00p\x00o\x00', data):
    off = m.start()
    # Decode surrounding UTF16
    start = max(0, off-20)
    chunk = data[start:off+80]
    try:
        decoded = chunk.decode('utf-16-le', 'replace')
        # Print only printable
        printable = ''.join(c if c.isprintable() and ord(c) < 256 else '?' for c in decoded)
        print(f"  @{off:#08x}: {printable}")
    except:
        pass

print("\n=== sysdiag.sys: PAGE section strings ===")
for s in pe.sections:
    sname = s.Name.rstrip(b'\x00').decode('ascii','replace')
    if 'PAGE' in sname:
        sec = data[s.PointerToRawData:s.PointerToRawData+s.SizeOfRawData]
        fbase = s.PointerToRawData
        for m in re.finditer(rb'[\x20-\x7e]{8,}', sec):
            print(f"  @{fbase+m.start():#08x}: {m.group().decode('ascii','replace')}")
        for m in re.finditer(rb'(?:[\x20-\x7e]\x00){8,}', sec):
            s2 = m.group().decode('utf-16-le','replace')
            print(f"  [W] @{fbase+m.start():#08x}: {s2}")

print("\n=== sysdiag.sys: Protection offset (0x87C) context ===")
# The key one: 0x87C = Protection field
target = struct.pack('<H', 0x87C)
for m in re.finditer(re.escape(target), data):
    off = m.start()
    ctx = data[max(0,off-12):off+12].hex()
    print(f"  @{off:#08x}: ctx={ctx}")

target32 = struct.pack('<I', 0x87C)
for m in re.finditer(re.escape(target32), data):
    off = m.start()
    ctx = data[max(0,off-12):off+12].hex()
    print(f"  [DWORD] @{off:#08x}: ctx={ctx}")

print("\n=== hrdevmon.sys: Stack attach target analysis ===")
path2 = r"E:\driver_research\amd_ryzen_master\hrdevmon.sys"
with open(path2, 'rb') as f:
    data2 = f.read()
pe2 = pefile.PE(data=data2)

# Which drivers does hrdevmon attach to?
# The string \Driver\volmgr, \Driver\usbhub etc. - get context around them
for drv in [b'\\Driver\\', b'\\Device\\']:
    for m in re.finditer(re.escape(b'\\'+ drv[1:] + b'\\'), data2):
        off = m.start()
        # Check if it's a UTF-16 match
        # Read surrounding bytes to decode full path
        if data2[off+1] == 0:  # UTF-16
            j = off
            chars = []
            while j < len(data2) - 1:
                lo = data2[j]
                hi = data2[j+1]
                if hi == 0 and lo >= 0x20:
                    chars.append(chr(lo))
                    j += 2
                else:
                    break
            name = ''.join(chars)
            print(f"  @{off:#08x}: {name}")
        else:
            end = data2.find(b'\x00', off)
            print(f"  @{off:#08x}: {data2[off:end].decode('ascii','replace')}")

pe2.close()
pe.close()
print("\nDONE.")

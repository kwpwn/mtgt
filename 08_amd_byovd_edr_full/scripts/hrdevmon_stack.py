#!/usr/bin/env python3
"""hrdevmon stack attach targets + IRP dispatch analysis."""
import struct, re, pefile
import sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

path = r"E:\driver_research\amd_ryzen_master\hrdevmon.sys"
with open(path, 'rb') as f:
    data = f.read()
pe = pefile.PE(data=data)

print("=== hrdevmon.sys: ALL wide strings ===")
for m in re.finditer(rb'(?:[\x20-\x7e]\x00){6,}', data):
    off = m.start()
    s = m.group().decode('utf-16-le', 'replace')
    print(f"  @{off:#08x}: {s}")

print("\n=== hrdevmon.sys: Sections detail ===")
for s in pe.sections:
    sname = s.Name.rstrip(b'\x00').decode('ascii','replace')
    print(f"  {sname}: VA={s.VirtualAddress:#x}, FileOff={s.PointerToRawData:#x}, Size={s.SizeOfRawData:#x}")
    sec = data[s.PointerToRawData:s.PointerToRawData+s.SizeOfRawData]
    # All ASCII strings
    for m in re.finditer(rb'[\x20-\x7e]{6,}', sec):
        txt = m.group().decode('ascii', 'replace')
        if any(kw in txt for kw in ['Driver', 'Device', 'DevData', 'Registry', 'volmgr', 'ftdisk', 'usbhub',
                                     'mskssrv', 'wdmaud', 'hrdevmon', 'HR::']):
            print(f"    [{sname}] @{s.PointerToRawData+m.start():#08x}: {txt}")

print("\n=== hrdevmon.sys: IoAttachDeviceToDeviceStackSafe call context ===")
# Find the import table entry for IoAttachDeviceToDeviceStackSafe
# Then find CALL instructions to that IAT entry
# First get the IAT address
iat_addr = None
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name and b'IoAttachDeviceToDeviceStackSafe' in imp.name:
                iat_addr = imp.address
                print(f"  IAT address for IoAttachDeviceToDeviceStackSafe: {iat_addr:#010x}")
                break

# Look for 0x6058 region in .rdata (where device names are)
print("\n=== hrdevmon.sys: .rdata section full dump ===")
for s in pe.sections:
    sname = s.Name.rstrip(b'\x00').decode('ascii','replace')
    if sname == '.rdata':
        sec = data[s.PointerToRawData:s.PointerToRawData+s.SizeOfRawData]
        fbase = s.PointerToRawData
        for i in range(0, len(sec), 16):
            chunk = sec[i:i+16]
            hex_p = ' '.join(f'{b:02x}' for b in chunk)
            asc_p = ''.join(chr(b) if 0x20<=b<=0x7e else '.' for b in chunk)
            print(f"  {fbase+i:#08x}: {hex_p:<48s}  {asc_p}")
        break

pe.close()
print("\nDONE.")

#!/usr/bin/env python3
"""Final targeted analysis: hrwfpdrv callout GUIDs, sysdiag watchdog, hrdevmon attach target."""
import struct, re, pefile

def read(path):
    with open(path, 'rb') as f:
        return f.read()

# ====== hrwfpdrv: extract all 16-byte blocks from .data section that look like GUIDs ======
print("="*70)
print("hrwfpdrv.sys: All GUID candidates from binary data region (callout GUIDs)")
print("="*70)
data = read(r"E:\driver_research\amd_ryzen_master\hrwfpdrv.sys")
pe = pefile.PE(data=data)

# Known GUIDs for reference
KNOWN = {
    bytes.fromhex("bfd186c1cd21 7e49 a0bb17425c885c58".replace(" ","")): "FWPM_LAYER_ALE_AUTH_CONNECT_V4",
}
# Unpack GUIDs from binary
def bytes_to_guid(b):
    d1, d2, d3 = struct.unpack_from('<IHH', b)
    d4 = b[8:16]
    return f"{{{d1:08X}-{d2:04X}-{d3:04X}-{d4[:2].hex().upper()}-{d4[2:].hex().upper()}}}"

for s in pe.sections:
    sname = s.Name.rstrip(b'\x00').decode('ascii','replace')
    if sname in ['.rdata', '.data']:
        sec = data[s.PointerToRawData:s.PointerToRawData+s.SizeOfRawData]
        fbase = s.PointerToRawData
        print(f"\nSection {sname} (file_off={fbase:#x}):")
        # Scan for 16-byte aligned blocks with decent entropy
        for i in range(0, len(sec)-16, 16):
            chunk = sec[i:i+16]
            d1 = struct.unpack_from('<I', chunk)[0]
            if d1 > 0x10000 and len(set(chunk)) >= 8 and not all(b == 0 for b in chunk):
                g = bytes_to_guid(chunk)
                print(f"  @{fbase+i:#08x}: {g}")
pe.close()

# ====== hrwfpdrv: look for redirect-related WFP functions in .text ======
print("\n")
print("="*70)
print("hrwfpdrv.sys: Connection redirect API usage (FwpsRedirectHandle*)")
print("="*70)
# Already found in strings: FwpsRedirectHandleCreate0, FwpsQueryConnectionRedirectState0
# These are used for ALE_CONNECT_REDIRECT callouts
# Check .data section for provider/sublayer GUIDs
# The callout is registered on FWPM_LAYER_ALE_CONNECT_REDIRECT_V4 if these are present

# ====== sysdiag: .asmstub section ======
print("\n")
print("="*70)
print("sysdiag.sys: .asmstub section content")
print("="*70)
data = read(r"E:\driver_research\amd_ryzen_master\sysdiag.sys")
pe = pefile.PE(data=data)
for s in pe.sections:
    sname = s.Name.rstrip(b'\x00').decode('ascii','replace')
    if sname == '.asmstub':
        sec = data[s.PointerToRawData:s.PointerToRawData+s.SizeOfRawData]
        print(f"Section .asmstub: VA={s.VirtualAddress:#x}, file_off={s.PointerToRawData:#x}, size={s.SizeOfRawData:#x}")
        print("Hex dump:")
        for i in range(0, min(len(sec), 0x100), 16):
            chunk = sec[i:i+16]
            hex_p = ' '.join(f'{b:02x}' for b in chunk)
            asc_p = ''.join(chr(b) if 0x20<=b<=0x7e else '.' for b in chunk)
            print(f"  {s.PointerToRawData+i:#08x}: {hex_p:<48s}  {asc_p}")
        break

# ====== sysdiag: PAGE section ======
print("\n")
print("="*70)
print("sysdiag.sys: PAGE section (pageable code - usually callbacks)")
print("="*70)
for s in pe.sections:
    sname = s.Name.rstrip(b'\x00').decode('ascii','replace')
    if sname == 'PAGE':
        sec = data[s.PointerToRawData:s.PointerToRawData+s.SizeOfRawData]
        print(f"Section PAGE: VA={s.VirtualAddress:#x}, file_off={s.PointerToRawData:#x}, size={s.SizeOfRawData:#x}")
        # Extract strings from PAGE section
        for m in re.finditer(rb'[\x20-\x7e]{8,}', sec):
            s2 = m.group().decode('ascii','replace')
            print(f"  @{s.PointerToRawData+m.start():#08x}: {s2}")
        # UTF16
        for m in re.finditer(rb'(?:[\x20-\x7e]\x00){8,}', sec):
            s2 = m.group().decode('utf-16-le','replace')
            print(f"  [W] @{s.PointerToRawData+m.start():#08x}: {s2}")
        break

# ====== sysdiag: watchdog thread - look for PsLookupProcessByProcessId usage patterns ======
print("\n")
print("="*70)
print("sysdiag.sys: LSASS protection - checking for process name 'lsass' or PID patterns")
print("="*70)
# Search for lsass string
for pat in [b'lsass', b'l\x00s\x00a\x00s\x00s\x00']:
    for m in re.finditer(re.escape(pat), data, re.IGNORECASE):
        ctx = data[max(0,m.start()-30):m.start()+50]
        printable = ''.join(chr(b) if 0x20<=b<=0x7e else '.' for b in ctx)
        print(f"  @{m.start():#08x}: {printable}")

# ====== sysdiag: minifilter registration ======
print("\n")
print("="*70)
print("sysdiag.sys: Minifilter (FltRegisterFilter) evidence")
print("="*70)
# Check for FLTMGR registration structure - look for strings passed to FltRegisterFilter
# The altitude string (numeric altitude like "320000")
for m in re.finditer(rb'\d{5,6}', data):
    val = int(m.group())
    if 10000 <= val <= 999999:
        off = m.start()
        # Check if it's in .rdata (likely string constant)
        for s in pe.sections:
            if s.PointerToRawData <= off < s.PointerToRawData + s.SizeOfRawData:
                sname = s.Name.rstrip(b'\x00').decode('ascii','replace')
                ctx = data[max(0,off-8):off+12]
                asc = ''.join(chr(b) if 0x20<=b<=0x7e else '.' for b in ctx)
                if sname == '.rdata':
                    print(f"  @{off:#08x} [{sname}]: {m.group().decode()} (ctx: {asc!r})")
                break

# Also look for altitude as wide string
altitude_pattern = rb'(?:[\x30-\x39]\x00){4,7}'
for m in re.finditer(altitude_pattern, data):
    s2 = m.group().decode('utf-16-le', 'replace')
    if s2.isdigit() and 10000 <= int(s2) <= 999999:
        print(f"  [W] @{m.start():#08x}: altitude candidate = {s2}")

pe.close()

# ====== hrdevmon: IoAttachDeviceToDeviceStackSafe target analysis ======
print("\n")
print("="*70)
print("hrdevmon.sys: Device attach targets (driver names in strings)")
print("="*70)
data = read(r"E:\driver_research\amd_ryzen_master\hrdevmon.sys")
pe = pefile.PE(data=data)
print("Driver names found (these are likely attach targets):")
for s in pe.sections:
    sname = s.Name.rstrip(b'\x00').decode('ascii','replace')
    sec = data[s.PointerToRawData:s.PointerToRawData+s.SizeOfRawData]
    # Wide strings with \Driver\
    for m in re.finditer(rb'\\\x00D\x00r\x00i\x00v\x00e\x00r\x00\\\x00', sec):
        # Read full name
        start = m.start()
        chars = []
        i = start
        while i + 1 < len(sec):
            lo = sec[i]; hi = sec[i+1]
            if hi == 0 and 0x20 <= lo <= 0x7e:
                chars.append(chr(lo))
                i += 2
            else:
                break
        name = ''.join(chars)
        print(f"  [{sname}] @{s.PointerToRawData+start:#08x}: {name}")

print("\nDevice class GUIDs in hrdevmon (device type monitoring):")
# The GUIDs from hrdevmon indicate which device classes it monitors
guid_meanings = {
    "{36FC9E60-C465-11CF-8056-444553540000}": "USB Bus (Generic) - monitors USB devices",
    "{4d36e96c-e325-11ce-bfc1-08002be10318}": "Media (Sound/Audio) devices",
    "{eec5ad98-8080-425f-922a-dabf3de3f69a}": "WPD (Portable/MTP devices: phones, cameras)",
    "{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}": "Bluetooth",
    "{4d36e967-e325-11ce-bfc1-08002be10318}": "Disk Drive devices",
    "{88bae032-5a81-49f0-bc3d-a4ff138216d6}": "USB Device (generic endpoint)",
    "{3F966BD9-FA04-4ec5-991C-D326973B5128}": "HID (Human Interface Devices: keyboard, mouse)",
}
for guid, meaning in guid_meanings.items():
    print(f"  {guid}: {meaning}")

pe.close()
print("\nDONE.")

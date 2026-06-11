#!/usr/bin/env python3
"""Deep scan hrwfpdrv.sys - inspect the suspicious strings and GUID region."""
import struct, re, pefile

path = r"E:\driver_research\amd_ryzen_master\hrwfpdrv.sys"
with open(path, 'rb') as f:
    data = f.read()

pe = pefile.PE(data=data)

print("=== hrwfpdrv.sys FULL STRING DUMP (interesting) ===")
# Extract all strings >= 5 chars
import sys

def all_strings(buf, min_len=5):
    results = []
    # ASCII
    for m in re.finditer(rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}', buf):
        results.append((m.start(), 'A', m.group().decode('ascii', errors='replace')))
    # UTF-16 LE
    for m in re.finditer(rb'(?:[\x20-\x7e]\x00){' + str(min_len).encode() + rb',}', buf):
        s = m.group().decode('utf-16-le', errors='replace')
        results.append((m.start(), 'W', s))
    results.sort(key=lambda x: x[0])
    return results

# Section offsets
for s in pe.sections:
    sname = s.Name.rstrip(b'\x00').decode('ascii', errors='replace')
    print(f"\nSection {sname}: file_offset={s.PointerToRawData:#x}  size={s.SizeOfRawData:#x}")

print("\n=== ALL STRINGS in hrwfpdrv.sys ===")
seen = set()
c2_patterns = [
    'HTTP', 'http', 'Authorization', 'Content-', 'Host:', 'User-Agent',
    'NTLMSSP', 'SMB', 'IPC', 'DcRat', 'SolrAuth', 'chunked', 'gzip',
    '.sqlite', '.db', '.key', 'process.main', 'child_process', 'execSync',
    '__import__', 'os.popen', 'os.system', 'exec(', 'filepath', 'originalFilename',
    'filename=', '.php', 'combo', 'activemq', 'broker', 'addNetwo',
    'n8n', '.key', 'code',
]

for off, enc, s in all_strings(data, min_len=5):
    if s in seen:
        continue
    seen.add(s)
    interesting = any(p in s for p in c2_patterns) or \
                  s.startswith('\\') or \
                  re.match(r'\{[0-9a-fA-F]{8}-', s) or \
                  any(kw in s for kw in ['Fwp', 'Ndis', 'Device', 'Driver', 'Registry',
                                          'Io', 'Ps', 'Ob', 'Ke', 'Mm', 'Ex', 'Zw', 'Rtl',
                                          'lsass', 'LSASS', 'Huorong', 'hips', 'AV',
                                          'protect', 'inject', 'hook', 'bypass'])
    if interesting:
        print(f"  [{enc} @{off:#08x}] {s!r}")

print("\n=== FULL .rdata dump of GUID region (0x022400-0x022900) ===")
for s in pe.sections:
    sname = s.Name.rstrip(b'\x00').decode('ascii', errors='replace')
    if sname == '.rdata':
        file_off = s.PointerToRawData
        # The GUIDs were at 0x022458, 0x022498, etc.
        # Section VirtualAddress = 0x21000, PointerToRawData = 0x20000
        # So file offset 0x022458 is in .rdata
        start = 0x022400
        end = 0x022900
        region = data[start:end]
        print(f"File offsets {start:#x}-{end:#x}:")
        for i in range(0, len(region), 16):
            chunk = region[i:i+16]
            hex_p = ' '.join(f'{b:02x}' for b in chunk)
            asc_p = ''.join(chr(b) if 0x20<=b<=0x7e else '.' for b in chunk)
            print(f"  {start+i:#08x}: {hex_p:<48s}  {asc_p}")
        break

# Check: is the suspicious data (HTTP strings, exploit patterns) in the .text or .rdata?
print("\n=== LOCATING suspicious strings in sections ===")
suspicious = [b'DcRat Server', b'NTLMSSP', b'SolrAuth', b'child_process', b'__import__', b'activemq',
              b'Authorization:', b'filename=', b'.sqlite', b'execSync', b'os.popen', b'filepath']
for pat in suspicious:
    for m in re.finditer(re.escape(pat), data):
        off = m.start()
        # Find which section
        sec_name = "unknown"
        for s in pe.sections:
            if s.PointerToRawData <= off < s.PointerToRawData + s.SizeOfRawData:
                sec_name = s.Name.rstrip(b'\x00').decode('ascii', errors='replace')
                break
        print(f"  @{off:#08x} [{sec_name}]: {pat.decode()}")

pe.close()
print("\nDONE.")

#!/usr/bin/env python3
"""Scan hrwfpdrv.sys for binary-packed WFP layer/callout GUIDs."""
import struct
import re

# Well-known WFP FWPM_LAYER_* GUIDs in packed binary form (little-endian)
# Format: {Data1, Data2, Data3, Data4[8]}
# We represent as 16-byte sequence

def guid_to_bytes(g_str):
    """Convert '{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}' to 16 bytes (LE struct)."""
    g = g_str.strip('{}')
    parts = g.split('-')
    d1 = int(parts[0], 16)
    d2 = int(parts[1], 16)
    d3 = int(parts[2], 16)
    d4 = bytes.fromhex(parts[3] + parts[4])
    return struct.pack('<IHH', d1, d2, d3) + d4

# Known WFP layer GUIDs
WFP_LAYERS = {
    # ALE
    "{c86fd1bf-21cd-497e-a0bb-17425c885c58}": "FWPM_LAYER_ALE_AUTH_CONNECT_V4",
    "{4a72393b-319f-44bc-84c3-ba54dcb3b6b4}": "FWPM_LAYER_ALE_AUTH_CONNECT_V6",
    "{e1cd9fe7-f4b5-4273-96c0-592e487b8650}": "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4",
    "{a3b3ab6b-a3c6-4648-9d8e-f942ee1ddc39}": "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6",
    "{44e996ad-5f1e-4e33-9cde-c2a69e29d3c8}": "FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4",
    "{efea1f20-e8b4-4c17-9f7b-07ae1d00d4f2}": "FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6",
    "{de80d6e1-e832-4645-bf2d-7ceb5e08ec2a}": "FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4",
    "{f36a2eb4-ef91-4c27-8a40-9e4ef9f8a00e}": "FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6",
    "{1247d66d-0b60-4a15-8d44-7155d0f53a0c}": "FWPM_LAYER_ALE_BIND_REDIRECT_V4",
    "{f263a37d-c15e-4a3b-afcc-4b6df6a1ce19}": "FWPM_LAYER_ALE_CONNECT_REDIRECT_V4",
    "{587e54a7-8046-4a69-a449-54c69945c4d8}": "FWPM_LAYER_ALE_CONNECT_REDIRECT_V6",
    "{3b89653c-c170-49e4-b1cd-e0eeeee19a3e}": "FWPM_LAYER_ALE_AUTH_LISTEN_V4",
    # Transport
    "{c91ef6e8-6b29-4c96-8752-29b4f2a43892}": "FWPM_LAYER_INBOUND_TRANSPORT_V4",
    "{9f4060e9-4f57-4b7e-af51-e0e6ad8940e5}": "FWPM_LAYER_OUTBOUND_TRANSPORT_V4",
    "{bb9a7a3f-40d8-4b29-820d-2aafaf1e0f9e}": "FWPM_LAYER_INBOUND_TRANSPORT_V6",
    "{19b597e1-0e28-4527-bd55-e8a39ee14a8e}": "FWPM_LAYER_OUTBOUND_TRANSPORT_V6",
    # Stream
    "{3b89653c-c170-49e4-b1cd-e0eeeee19a3e}": "FWPM_LAYER_ALE_AUTH_LISTEN_V4",
    "{b3a73f79-c1ab-48d5-8f29-b196cf5e7acf}": "FWPM_LAYER_STREAM_V4",
    "{0e3e5a42-c8c8-4f7e-ad83-6b7c8f76a6e0}": "FWPM_LAYER_STREAM_V6",
    # Datagram
    "{09e61aea-d214-46e2-9b21-b26b0b2f2b4e}": "FWPM_LAYER_DATAGRAM_DATA_V4",
    "{e1443cbe-bfe0-4e61-b7cb-38ca10d5b0e5}": "FWPM_LAYER_DATAGRAM_DATA_V6",
    # IPFORWARD
    "{a82acc24-4ee1-4ee1-b465-fd1d25cb10a4}": "FWPM_LAYER_IPFORWARD_V4",
    # Inbound ICMP
    "{1eccda1b-978c-4a61-b6a2-a4a2498a0894}": "FWPM_LAYER_INBOUND_ICMP_ERROR_V4",
    # Network
    "{b16b0a6e-2b2a-41a3-8b39-bd3ffc855ff8}": "FWPM_LAYER_INBOUND_IPPACKET_V4",
    "{f52032cb-991c-46e7-971d-2689a3eea1ab}": "FWPM_LAYER_OUTBOUND_IPPACKET_V4",
}

def scan_file_for_guids(path):
    with open(path, 'rb') as f:
        data = f.read()

    print(f"\n{'='*60}")
    print(f"WFP GUID SCAN: {path}")
    print('='*60)

    found = []
    for guid_str, name in WFP_LAYERS.items():
        try:
            b = guid_to_bytes(guid_str)
            for m in re.finditer(re.escape(b), data):
                print(f"  @{m.start():#08x}: {guid_str} => {name}")
                found.append((m.start(), guid_str, name))
        except Exception as e:
            print(f"  Error with {guid_str}: {e}")

    if not found:
        print("  No known WFP layer GUIDs found in binary form")

    # Also scan for any 16-byte sequences that look like GUIDs near known WFP function imports
    # and try to decode them
    print("\n[ALL 16-byte GUID-like sequences in .rdata section]")
    import pefile
    pe = pefile.PE(data=data)
    for s in pe.sections:
        name = s.Name.rstrip(b'\x00').decode('ascii', errors='replace')
        if name in ['.rdata', '.data']:
            sec_data = data[s.PointerToRawData:s.PointerToRawData+s.SizeOfRawData]
            sec_base = s.PointerToRawData
            # Scan for sequences that could be GUIDs
            for i in range(0, len(sec_data) - 16, 4):
                # A GUID's Data1 is usually a "random" DWORD, Data2/Data3 are WORDs
                # Just display all 16-byte aligned sequences as potential GUIDs
                # Filter: first 4 bytes non-zero, last 8 bytes not all same
                chunk = sec_data[i:i+16]
                d1, d2, d3 = struct.unpack_from('<IHH', chunk)
                d4 = chunk[8:]
                if d1 > 0x10000 and not all(b == 0 for b in chunk) and not all(b == chunk[0] for b in chunk):
                    guid_repr = f"{{{d1:08X}-{d2:04X}-{d3:04X}-{d4[:2].hex().upper()}-{d4[2:].hex().upper()}}}"
                    # Check if it matches known pattern (high entropy)
                    entropy = len(set(chunk))
                    if entropy >= 8:  # Likely a real GUID
                        known = WFP_LAYERS.get(guid_repr.lower(), "")
                        if known:
                            print(f"  @{sec_base+i:#08x}: {guid_repr} => {known}")
    pe.close()
    return found

# Scan all three
for path in [
    r"E:\driver_research\amd_ryzen_master\hrdevmon.sys",
    r"E:\driver_research\amd_ryzen_master\hrwfpdrv.sys",
    r"E:\driver_research\amd_ryzen_master\sysdiag.sys",
]:
    scan_file_for_guids(path)

# Also print hex dump of .rdata section of hrwfpdrv to find GUID blocks
print("\n\n=== hrwfpdrv .rdata hex dump (first 0x400 bytes) ===")
with open(r"E:\driver_research\amd_ryzen_master\hrwfpdrv.sys", 'rb') as f:
    data = f.read()
import pefile
pe = pefile.PE(data=data)
for s in pe.sections:
    name = s.Name.rstrip(b'\x00').decode('ascii', errors='replace')
    if name == '.rdata':
        rdata = data[s.PointerToRawData:s.PointerToRawData+min(0x800, s.SizeOfRawData)]
        for i in range(0, len(rdata), 16):
            chunk = rdata[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            asc_part = ''.join(chr(b) if 0x20<=b<=0x7e else '.' for b in chunk)
            print(f"  {s.PointerToRawData+i:#08x}: {hex_part:<48s}  {asc_part}")
        break
pe.close()
print("\nDONE.")

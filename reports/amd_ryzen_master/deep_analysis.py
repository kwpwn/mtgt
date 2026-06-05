#!/usr/bin/env python3
"""Deep analysis pass: GUIDs, WFP layers, watchdog patterns, EPROCESS offsets."""

import struct
import re
import os

DRIVERS = {
    "hrdevmon": r"E:\driver_research\amd_ryzen_master\hrdevmon.sys",
    "hrwfpdrv": r"E:\driver_research\amd_ryzen_master\hrwfpdrv.sys",
    "sysdiag":  r"E:\driver_research\amd_ryzen_master\sysdiag.sys",
}

# Known GUID mappings for device class GUIDs and WFP layer GUIDs
KNOWN_GUIDS = {
    # Device class GUIDs
    "{36FC9E60-C465-11CF-8056-444553540000}": "GUID_DEVCLASS_USB (USB devices)",
    "{4d36e96c-e325-11ce-bfc1-08002be10318}": "GUID_DEVCLASS_SOUND (Sound devices)",
    "{eec5ad98-8080-425f-922a-dabf3de3f69a}": "GUID_DEVCLASS_WPD (Portable devices)",
    "{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}": "GUID_DEVCLASS_BLUETOOTH",
    "{4d36e967-e325-11ce-bfc1-08002be10318}": "GUID_DEVCLASS_DISKDRIVE",
    "{88bae032-5a81-49f0-bc3d-a4ff138216d6}": "GUID_DEVCLASS_USB_DEVICE (generic USB)",
    "{3F966BD9-FA04-4ec5-991C-D326973B5128}": "GUID_DEVCLASS_HIDClass (HID devices)",
    # WFP Layer GUIDs
    "{c86fd1bf-21cd-497e-a0bb-17425c885c58}": "FWPM_LAYER_ALE_AUTH_CONNECT_V4",
    "{4a72393b-319f-44bc-84c3-ba54dcb3b6b4}": "FWPM_LAYER_ALE_AUTH_CONNECT_V6",
    "{e1cd9fe7-f4b5-4273-96c0-592e487b8650}": "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4",
    "{a3b3ab6b-a3c6-4648-9d8e-f942ee1ddc39}": "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6",
    "{44e996ad-5f1e-4e33-9cde-c2a69e29d3c8}": "FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4",
    "{efea1f20-e8b4-4c17-9f7b-07ae1d00d4f2}": "FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6",
    "{de80d6e1-e832-4645-bf2d-7ceb5e08ec2a}": "FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4",
    "{f36a2eb4-ef91-4c27-8a40-9e4ef9f8a00e}": "FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6",
    "{c91ef6e8-6b29-4c96-8752-29b4f2a43892}": "FWPM_LAYER_INBOUND_TRANSPORT_V4",
    "{9f4060e9-4f57-4b7e-af51-e0e6ad8940e5}": "FWPM_LAYER_OUTBOUND_TRANSPORT_V4",
    "{bb9a7a3f-40d8-4b29-820d-2aafaf1e0f9e}": "FWPM_LAYER_INBOUND_TRANSPORT_V6",
    "{19b597e1-0e28-4527-bd55-e8a39ee14a8e}": "FWPM_LAYER_OUTBOUND_TRANSPORT_V6",
    "{b3a73f79-c1ab-48d5-8f29-b196cf5e7acf}": "FWPM_LAYER_STREAM_V4",
    "{0e3e5a42-c8c8-4f7e-ad83-6b7c8f76a6e0}": "FWPM_LAYER_STREAM_V6",
    "{09e61aea-d214-46e2-9b21-b26b0b2f2b4e}": "FWPM_LAYER_DATAGRAM_DATA_V4",
    "{e1443cbe-bfe0-4e61-b7cb-38ca10d5b0e5}": "FWPM_LAYER_DATAGRAM_DATA_V6",
}

def scan_guids_binary(data):
    """Find all GUIDs in binary data (both packed struct form and string form)."""
    results = []
    # String form
    pattern = rb'\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}'
    for m in re.finditer(pattern, data):
        g = m.group().decode('ascii')
        results.append(('STR', m.start(), g))
    # Wide string form
    # Search for { as UTF16
    wide_pattern = rb'(?:\{[\x00])(?:[0-9a-fA-F][\x00]){8}(?:-[\x00])(?:[0-9a-fA-F][\x00]){4}(?:-[\x00])(?:[0-9a-fA-F][\x00]){4}(?:-[\x00])(?:[0-9a-fA-F][\x00]){4}(?:-[\x00])(?:[0-9a-fA-F][\x00]){12}(?:\}[\x00])'
    # Simpler UTF16 extraction
    for i in range(len(data) - 80):
        if data[i] == ord('{') and data[i+1] == 0:
            s = []
            j = i
            while j < len(data) - 1:
                c = data[j]
                if data[j+1] != 0:
                    break
                s.append(chr(c))
                j += 2
                if c == '}':
                    break
            candidate = ''.join(s)
            if re.match(r'^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$', candidate):
                results.append(('WIDE', i, candidate))
    # Packed GUID (binary form: 4+2+2+8 bytes = 16 bytes)
    # We'll look for GUID structs - harder to detect without context
    # Skip for now unless needed
    return results

def find_patterns(data, drv_name):
    print(f"\n{'='*70}")
    print(f"DEEP ANALYSIS: {drv_name}")
    print('='*70)

    # 1. All GUIDs
    print("\n[ALL GUIDs FOUND]")
    guids = scan_guids_binary(data)
    seen_guids = set()
    for enc, off, g in guids:
        if g in seen_guids:
            continue
        seen_guids.add(g)
        known = KNOWN_GUIDS.get(g.lower(), KNOWN_GUIDS.get(g, "Unknown"))
        print(f"  [{enc} @{off:#08x}] {g} => {known}")

    # 2. Search for "Protection" patterns (EPROCESS.Protection watchdog)
    print("\n[PROTECTION/EPROCESS PATTERNS]")
    protection_patterns = [
        b"Protection",
        b"SignatureLevel",
        b"SectionSignatureLevel",
        b"lsass",
        b"LSASS",
        b"ActiveProcessLinks",
        b"UniqueProcessId",
    ]
    for p in protection_patterns:
        # ASCII
        for m in re.finditer(p, data, re.IGNORECASE):
            ctx_start = max(0, m.start() - 20)
            ctx = data[ctx_start:m.start()+len(p)+20]
            printable = ''.join(chr(c) if 0x20 <= c <= 0x7e else '.' for c in ctx)
            print(f"  ASCII [{p.decode()}] @{m.start():#08x}: {printable}")
        # UTF-16
        wide = b'\x00'.join(bytes([c]) for c in p) + b'\x00'
        for m in re.finditer(re.escape(wide), data, re.IGNORECASE):
            print(f"  UTF16 [{p.decode()}] @{m.start():#08x}")

    # 3. Hardcoded offsets (potential EPROCESS field offsets for Win10/11)
    # Look for specific dword constants used in watchdog (0x878, 0x87a, 0x6F8, etc.)
    print("\n[POTENTIAL EPROCESS OFFSETS (hardcoded DWORD constants in .rdata/.data)]")
    # We scan .rdata section for small dword values that look like offsets
    # Typical EPROCESS offsets on Win10 21H2 x64:
    # Protection: 0x87A, SignatureLevel: 0x878, UniqueProcessId: 0x440
    # ActiveProcessLinks: 0x448, ImageFileName: 0x5A8
    interesting_offsets = {
        0x440: "UniqueProcessId (W10 21H2)",
        0x448: "ActiveProcessLinks (W10 21H2)",
        0x5A8: "ImageFileName (W10 21H2)",
        0x878: "SignatureLevel (W10 21H2)",
        0x87A: "SectionSignatureLevel (W10 21H2)",
        0x87C: "Protection (W10 21H2)",
        0x450: "UniqueProcessId (W11 22H2)",
        0x540: "ActiveProcessLinks (W11 22H2)",
        0x5B0: "ImageFileName (W11 22H2)",
        0x880: "SignatureLevel (W11 22H2)",
        0x882: "SectionSignatureLevel (W11 22H2)",
        0x884: "Protection (W11 22H2)",
        # Also common
        0x6F8: "ActiveProcessLinks (W10 1903)",
        0x2E8: "UniqueProcessId (W7)",
    }
    found_offsets = set()
    for i in range(0, len(data)-4, 4):
        v = struct.unpack_from('<I', data, i)[0]
        if v in interesting_offsets and v not in found_offsets:
            found_offsets.add(v)
            # Get surrounding bytes
            ctx = data[max(0,i-16):i+20].hex()
            print(f"  @{i:#08x} DWORD={v:#06x} => {interesting_offsets[v]}  ctx={ctx}")

    # 4. ObRegisterCallbacks usage (often resolved dynamically)
    print("\n[ObRegisterCallbacks / DYNAMIC RESOLUTION]")
    obcb = b"ObRegisterCallbacks"
    for m in re.finditer(obcb, data):
        print(f"  ASCII @{m.start():#08x}: ObRegisterCallbacks")
    # Also UTF16
    obcb_w = b'O\x00b\x00R\x00e\x00g\x00i\x00s\x00t\x00e\x00r\x00C\x00a\x00l\x00l\x00b\x00a\x00c\x00k\x00s\x00'
    for m in re.finditer(re.escape(obcb_w), data):
        print(f"  UTF16 @{m.start():#08x}: ObRegisterCallbacks")

    # 5. MmGetSystemRoutineAddress usage (dynamic import)
    print("\n[DYNAMIC IMPORTS via MmGetSystemRoutineAddress]")
    # These would appear as Unicode strings passed to MmGetSystemRoutineAddress
    dyn_funcs = [
        "ZwWriteVirtualMemory", "ZwResumeProcess", "PsResumeProcess",
        "ObRegisterCallbacks", "PsSetCreateProcessNotifyRoutineEx",
        "PsSetCreateProcessNotifyRoutineEx2", "EtwRegister", "EtwWrite",
        "PspCreateProcessNotifyRoutine", "CmRegisterCallbackEx",
        "IoCreateDeviceSecure", "PsRemoveCreateThreadNotifyRoutine",
    ]
    for fn in dyn_funcs:
        # UTF16
        fn_wide = '\x00'.join(fn).encode() + b'\x00'
        for m in re.finditer(re.escape(fn_wide), data):
            print(f"  UTF16 @{m.start():#08x}: {fn}")
        # ASCII
        for m in re.finditer(fn.encode(), data):
            print(f"  ASCII @{m.start():#08x}: {fn}")

    # 6. Look for hrdevmon IRP dispatch table patterns
    # Check for \Device\HR::DevMon references
    print("\n[DEVICE NAME REFERENCES]")
    device_refs = [
        b"HR::DevMon", b"HR::Base", b"HR::ActMon", b"HR::DTrampo",
        b"HRFW_BASE_DEV", b"HrWfpFlt", b"SysDiag::IOKit", b"SysDiag::SysUtils",
    ]
    for ref in device_refs:
        for m in re.finditer(ref, data):
            print(f"  ASCII @{m.start():#08x}: {ref.decode()}")
        # Wide
        wide_ref = b'\x00'.join(bytes([c]) for c in ref) + b'\x00'
        for m in re.finditer(re.escape(wide_ref), data):
            print(f"  UTF16 @{m.start():#08x}: {ref.decode()}")

    # 7. Look for nxeng references (bypass target?)
    print("\n[NXENG / COMPETITOR REFERENCES]")
    for keyword in [b"nxeng", b"TVSecure", b"bindflt", b"hrBackup"]:
        for m in re.finditer(keyword, data, re.IGNORECASE):
            ctx_start = max(0, m.start()-10)
            ctx_end = min(len(data), m.start()+len(keyword)+30)
            ctx = ''.join(chr(c) if 0x20<=c<=0x7e else '.' for c in data[ctx_start:ctx_end])
            print(f"  @{m.start():#08x}: {ctx}")
        # Wide
        wide_kw = b'\x00'.join(bytes([c]) for c in keyword.lower()) + b'\x00'
        for m in re.finditer(re.escape(wide_kw), data, re.IGNORECASE):
            ctx = ''.join(chr(data[i]) if 0x20<=data[i]<=0x7e else '.' for i in range(max(0,m.start()-20), min(len(data),m.start()+len(wide_kw)+40), 2))
            print(f"  UTF16 @{m.start():#08x}: {ctx}")


for name, path in DRIVERS.items():
    with open(path, 'rb') as f:
        data = f.read()
    find_patterns(data, name)

print("\n\nDONE.")

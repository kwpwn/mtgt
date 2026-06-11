# AMD Ryzen Master BYOVD — Full EDR Bypass Suite

Physical R/W via `AMDRyzenMasterDriverV20` (IOCTL `0x81112F08`/`0x81112F0C`).  
No extra driver, no PDB, Admin rights only.

---

## Structure

```
edr_bypass.c / .exe     ← MAIN tool (all bypass modules combined)
docs/                   ← research notes, technique specs, analysis
standalone/             ← individual technique C tools
scripts/                ← Python IDA/analysis scripts
archive/                ← old approaches / superseded code
```

---

## Main Tool — edr_bypass.c

All techniques integrated. Build:
```bash
x86_64-w64-mingw32-gcc -O2 -Wall -Wno-unused-function \
    -Wno-format-truncation -Wno-unused-but-set-variable \
    -o edr_bypass.exe edr_bypass.c \
    -lkernel32 -ladvapi32 -lversion -ldbghelp -lntdll
```

Implemented modules:

| § | Module | Technique |
|---|--------|-----------|
| §1 | Ps* notify arrays | PspCreate/Thread/LoadImage — LEA scan |
| §2 | OB callbacks | TypeList walk + Enabled flag clear |
| §3 | Minifilter PreOp | LIST_ENTRY unlink + Method A.6/B.2 |
| §4 | CM callbacks | Pool scan (altitude + no-altitude) |
| §5 | WFP callouts | Pool scan, zero classifyFn/notifyFn |
| §6 | ETW-TI | Method A (export patch) + B (GUID scan) + C (ntoskrnl section scan) |
| §7a | Token theft LPE | EPROCESS.Token swap via sysdiag |
| §7b | Sysdiag 3-layer | Watchdog KDPC + HIPS bit + PID whitelist |
| §7c | SSDT hook clear | KiServiceTable vs disk PE compare |
| §7d | ETW-TI Method C | ntoskrnl .data/ALMOSTR* section scan |
| §7e | g_CiOptions patch | CI.dll pattern scan → DSE disable |
| §7f | DKOM driver hiding | PsLoadedModuleList InLoadOrder+InMemoryOrder unlink |
| §7g | hrdevmon IRP hook | PA scan DriverObject → MajorFunction[CREATE,READ] → nop |
| §8 | PPL bypass | EPROCESS.Protection → 0 via sysdiag LOCK XCHG |

---

## docs/

| File | Nội dung |
|------|----------|
| `EXPLOIT_TECHNIQUES.md` | Master checklist — status (Done/TODO) + file reference |
| `EXPLOIT_DEEP_DIVE.md` | Full implementation guide từng kỹ thuật |
| `AMD_DRIVER_REVERSE.md` | IDA reverse engineering of AMDRyzenMasterDriver.sys |
| `HUORONG_ANALYSIS.md` | Huorong (火绒) kernel internals |
| `WDFILTER_INTERNALS.md` | Windows Defender WdFilter internals |
| `EDR_BYPASS_INTERNALS.md` | Complete technical reference |
| `FULL_BYPASS_RESEARCH_NOTE.md` | Research log (WD + Huorong + 360) |
| `LSASS_DUMP_NOTES.md` | LSASS dump progress notes |
| `WRITEUP.md` | Narrative writeup |
| `ASTRA64_VS_AMD_ANALYSIS.md` | Driver comparison analysis |

---

## standalone/

Standalone C tools — each technique as a separate binary:

| File | Status | Kỹ thuật |
|------|--------|----------|
| `dkom_hide.c` | ✅ Done | Process hiding (ActiveProcessLinks unlink) |
| `cr3_inject2.c` | ✅ Done | PML4 entry injection → zero-IOCTL LSASS read |
| `lsass_dump.c` | ✅ Done P1 | Direct LSASS PA dump (page table walk + MiniDump) |
| `ssdt_hook.c` | ✅ Done P2 | NT SSDT transient hook via CC region + ZwTestAlert |
| `pte_flip.c` | ✅ Done P3 | PTE NX-bit flip via MmPteBase + CR0.WP bypass |
| `handle_inject.c` | ✅ Done P3 | Handle table injection (Path A) + PPL bypass (Path B) |
| `sam_hive.c` | ✅ Done P3 | SAM hive physical mod — enable built-in Administrator |
| `irp_exec.c` | ✅ Done P3 | Ring-0 exec via IRP hook on null.sys → WriteFile trigger |
| `altsyscall_hook.c` | ✅ Done P4 | AltSystemCallHandlers hook — syscall intercept (Win11) |
| `kapc_inject.c` | ✅ Done P4 | KAPC injection into System worker thread |
| `lpe_system.c` | ✅ Done | LPE via token theft |
| `probe_devs.c` | ✅ Done | Device enumeration utility |
| `rootkit_loader.c` | ✅ Done | Reflective driver loader |
| `test_sysinfo.c` | utility | NtQuerySystemInformation test |
| `try_nt_open.c` | utility | NtOpenProcess test |
| `_patch_ksw.c` | utility | KSW patch helper |

---

## archive/

| File | Lý do archive |
|------|---------------|
| `cr3_inject.c` | PML4 v1 — ReadProcessMemory BSOD (wrong approach) |
| `cr3_swap.c` | DTB swap — BSOD vì kernel-half entries thay đổi dynamically |
| `dse_patch.c` | Standalone DSE patch — đã tích hợp vào edr_bypass.c §7e |
| `ppl_bypass.c` | Standalone PPL bypass — đã tích hợp vào edr_bypass.c §8 |
| `ANALYSIS_old.md` | AMD driver summary ngắn — superseded bởi AMD_DRIVER_REVERSE.md |

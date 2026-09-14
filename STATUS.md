# Full Chain Exploits — Status

## Chain 1: CVE-2026-6307 + CVE-2026-40369
- **Entry**: TurboFan FrameState CSE → addrof + fakeobj
- **Phases 1-6**: CONFIRMED on both Win10 & Win11
- **Renderer RCE**: Native code execution in sandboxed renderer (UNTRUSTED IL)
- **KASLR bypass**: EnumDeviceDrivers leaks ntoskrnl base from MEDIUM IL
- **PsInitialSystemProcess**: Found via PE export table (RVA 0x00cfc420 on Win10 21H2)
- **Stage2.bin**: 5805 bytes, sentinels verified, JMP/FPO correct

## Chain 2: crbug-542403045 + CVE-2026-6307 + CVE-2026-40369 (NEW)
- **Entry**: Array.prototype.sort element kind confusion → addrof
- **Root cause**: CanInlineArrayIteratingBuiltin unions {PACKED_SMI, PACKED} without
  agreement check. Inlined sort uses PACKED_SMI access on PACKED array.
  HeapObject ptrs read with Smi untag, written back with Smi tag → cage_offsets.
- **addrof**: leaked_val * 2 + 1 recovers compressed pointer
- **fakeobj**: CVE-2026-6307 FrameState CSE (same Chrome 146 version)
- **Sandbox escape**: CVE-2026-40369 kernel exploit (same stage2.bin)
- **Fix commit**: e0562d87ad9c17042b581582c99237d798572e67 (Aug 7 2026)
- **Status**: Code written, NEEDS TESTING

## Blocked (both chains)
- **CmpLayerVersionCount RVA**: NOT found on Win10 21H2 (Build 19044.7663)
  - Not in public PDB (symbol stripped)
  - Binary pattern scan (MOV [rsp+28h],0xFF8 + LEA) — NOT FOUND
  - **Root cause**: SystemLayerSnapshot (class 253) likely Win11-only
  - Need to run `diag_win10.py` on Win10 to confirm

## Pattern Scan (verified on Win11 25H2)
```
c7 44 24 28 f8 0f 00 00   MOV [rsp+28h], 0xFF8
48 8d 15 XX XX XX XX       LEA rdx, [rip+disp32]  -> CmpLayerVersionCount
```
- Win11 result: RVA 0x00ef709c (matches PDB)
- Win10 result: pattern not found

## Files
| File | Location | Purpose |
|------|----------|---------|
| orchestrator.py | E:\CVE\mtgt\ | Chain 1 orchestrator (CVE-2026-6307 entry) |
| orchestrator_sort.py | E:\CVE\mtgt\ | Chain 2 orchestrator (sort confusion entry) |
| exploit.html | E:\CVE\mtgt\ | Chain 1 V8 exploit display |
| exploit_sort.html | E:\CVE\mtgt\ | Chain 2 V8 exploit display |
| crbug-542403045-analysis.md | E:\CVE\mtgt\ | Sort confusion bug analysis |
| find_cmplayer.py | E:\CVE\mtgt\ | Standalone CmpLayerVersionCount RVA finder |
| diag_win10.py | E:\CVE\mtgt\ | Diagnostic: check if CVE-2026-40369 works on build |
| stage2.bin | fullchain-windows-CVE-2026-6307-40369\ | Kernel shellcode (PIC) |
| stage2_pic.c | fullchain-windows-CVE-2026-6307-40369\ | Stage2 source |

## Win10 Test Machine
- Chrome: C:\Users\kuvee\Downloads\chrome-win64\chrome-win64\chrome.exe
- Build: Win10 21H2 19044.7663
- ntoskrnl PDB GUID: C647466F42B0DF967125FB428EFB2FA11

## Next Steps
1. Test orchestrator_sort.py on Chrome 146 → confirm sort confusion addrof works
2. Run `diag_win10.py` on Win10 → confirm if class 253 exists
3. If class 253 missing → test on Win11 (original target: Build 26200.8875)
4. After full chains confirmed → build additional chains (see fullchain_candidates.md)

## CLI Usage
```
# Chain 1: CVE-2026-6307 entry
python orchestrator.py --chrome <chrome.exe> --stage2 <stage2.bin>

# Chain 2: Sort confusion entry
python orchestrator_sort.py --chrome <chrome.exe> --stage2 <stage2.bin>

# Manual RVA overrides (both chains)
python orchestrator_sort.py --chrome <chrome.exe> --rva-cmplayer 0xXXX --rva-psinitial 0xXXX
```

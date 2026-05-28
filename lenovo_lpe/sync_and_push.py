import subprocess, os, shutil

src     = r'E:\driver_research\lenovo_lpe'
dst     = r'E:\Windows-kernel-exploit-research-resource\03_byovd\01_physical-memory-rw\lenovo_lpe'
gitroot = r'E:\Windows-kernel-exploit-research-resource'

# Copy changed/new files
copy_files = [f for f in os.listdir(src)
              if f.endswith('.cpp') or f.endswith('.exe') or f == 'build.bat']
os.makedirs(dst, exist_ok=True)
for fn in sorted(copy_files):
    shutil.copy2(os.path.join(src, fn), os.path.join(dst, fn))
    print(f'  synced: {fn}')

def git(args):
    r = subprocess.run(['git'] + args, capture_output=True, text=True, cwd=gitroot)
    out = (r.stdout + r.stderr).strip()
    if out: print(out)
    return r.returncode

git(['add', '03_byovd/01_physical-memory-rw/lenovo_lpe/'])

status = subprocess.run(['git', 'status', '--short'],
                        capture_output=True, text=True, cwd=gitroot).stdout.strip()
if not status:
    print('\n[nothing to commit — files unchanged]')
    exit(0)

print('\ngit status:')
print(status)

msg = ("lenovo_lpe: add EDR blinding series 10-13\n\n"
       "- 10_ob_callback: removes ObRegisterCallbacks hooks from PsProcessType\n"
       "  and PsThreadType — EDR can no longer strip OpenProcess/OpenThread\n"
       "  access rights. Walks OBJECT_TYPE.CallbackList, zeros Pre/PostOperation\n"
       "  for non-system callbacks. Data-only, PG-safe, restore on exit.\n"
       "- 11_cm_callback: removes CmRegisterCallback slots from CmpCallBackVector\n"
       "  — blinds registry monitoring (persistence, IFEO, service install).\n"
       "  Scans CmRegisterCallbackEx for RIP-relative LEA to locate array.\n"
       "  Data-only, PG-safe, restore on exit.\n"
       "- 12_minifilter_blind: unlinks CALLBACK_NODEs from FLT_VOLUME\n"
       "  OperationLists (FltGlobals walk). EDR minifilters no longer receive\n"
       "  file I/O events for any attached volume. Uses LIST_ENTRY unlinking\n"
       "  (S12/0x12Dark April 2026 technique — KCFG/HVCI safe). Restore on exit.\n"
       "- 13_ppl_elevate: elevates own process to PPL/PP WinTcb level by writing\n"
       "  _PS_PROTECTION byte at EPROCESS+0x87A. EDR cannot PROCESS_TERMINATE\n"
       "  or PROCESS_VM_WRITE this process. Auto-restores after 30s (PG caution).\n"
       "- build_all.py updated for all 13 files\n"
       "- Rebuild all 01-13 EXEs")

rc = git(['commit', '-m', msg])
if rc == 0:
    git(['push'])
print('\nDone.')

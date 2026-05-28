import subprocess, sys

git_root = r'E:\Windows-kernel-exploit-research-resource'

def run(args, **kw):
    r = subprocess.run(args, capture_output=True, text=True, cwd=git_root, **kw)
    out = (r.stdout + r.stderr).strip()
    if out:
        print(out)
    return r.returncode

# Add the new folder
run(['git', 'add', '03_byovd/01_physical-memory-rw/lenovo_lpe/'])

# Commit
msg = ("add CVE-2025-8061 LnvMSRIO.sys LPE exploit series (01-08)\n\n"
       "8 standalone C++ exploit files demonstrating BYOVD techniques\n"
       "against LnvMSRIO.sys (Lenovo MSR I/O driver, CVE-2025-8061):\n\n"
       "01 KASLR defeat via LSTAR + physical PE scan\n"
       "02 Token stealing (DKOM, SYSTEM token copy)\n"
       "03 PPL bypass (EPROCESS.Protection zero)\n"
       "04 PreviousMode abuse (KTHREAD patch)\n"
       "05 DSE bypass (CI!g_CiOptions zero via RIP-relative scan)\n"
       "06 DKOM process hiding (ActiveProcessLinks unlink)\n"
       "07 IORing corruption (Win11 22H2+ arbitrary R/W)\n"
       "08 ETW-TI patch (blind kernel EDR sensors, RET stub)\n\n"
       "All files include MMIO skip (0xC0000000-0xFFFFFFFF) and\n"
       "4 KB page-by-page physical reads to prevent BSOD.\n"
       "Tested on Windows 10 19041 through Windows 11 26100.")

rc = run(['git', 'commit', '-m', msg])
if rc != 0:
    print('Commit failed')
    sys.exit(1)

# Push
rc = run(['git', 'push'])
if rc != 0:
    print('Push failed')
    sys.exit(1)

print('\nDone.')

import subprocess, os

src_dir = r'E:\driver_research\lenovo_lpe'
vcvars  = r'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat'

files = [
    ('00_diag',         'kernel32.lib advapi32.lib'),
    ('01_kaslr_defeat', 'kernel32.lib advapi32.lib'),
    ('02_token_steal',  'kernel32.lib advapi32.lib'),
    ('03_ppl_bypass',   'kernel32.lib advapi32.lib'),
    ('04_previousmode', 'kernel32.lib advapi32.lib'),
    ('05_dse_bypass',   'kernel32.lib advapi32.lib'),
    ('06_dkom_hide',    'kernel32.lib advapi32.lib'),
    ('07_ioring',       'kernel32.lib advapi32.lib'),
    ('08_etw_patch',    'kernel32.lib advapi32.lib'),
    ('09_callback_kill','kernel32.lib advapi32.lib'),
    ('10_ob_callback',  'kernel32.lib advapi32.lib'),
    ('11_cm_callback',  'kernel32.lib advapi32.lib'),
    ('12_minifilter_blind', 'kernel32.lib advapi32.lib'),
    ('13_ppl_elevate',  'kernel32.lib advapi32.lib'),
]

results = []
for name, libs in files:
    bat = os.path.join(src_dir, f'_b_{name}.bat')
    log = os.path.join(src_dir, f'_b_{name}.log')
    with open(bat, 'w') as f:
        f.write(f'@call "{vcvars}" >nul 2>&1\n')
        f.write(f'@cd /d "{src_dir}"\n')
        f.write(f'@cl /nologo /W3 /O2 /std:c++17 /Fe:{name}.exe {name}.cpp /link {libs}\n')
        f.write(f'@echo RC=%errorlevel%\n')
    with open(log, 'w') as logf:
        r = subprocess.run(['cmd.exe', '/c', bat], stdout=logf, stderr=subprocess.STDOUT, cwd=src_dir)
    with open(log) as lf:
        txt = lf.read().strip()
    rc_line = [l for l in txt.splitlines() if 'RC=' in l]
    rc = int(rc_line[-1].split('=')[1]) if rc_line else r.returncode
    status = 'OK' if rc == 0 else 'FAIL'
    print(f'[{status}] {name}.exe')
    if rc != 0:
        print(f'  {txt[-500:]}')
    results.append((name, rc))
    os.remove(bat)

print()
ok  = sum(1 for _, rc in results if rc == 0)
bad = sum(1 for _, rc in results if rc != 0)
print(f'Built: {ok}/{len(results)}  ({bad} failed)')

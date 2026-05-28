import subprocess, os, tempfile

src_dir = r'E:\driver_research\lenovo_lpe'

# Write a temp bat that runs vcvars + cl and captures output to a file
bat_path = os.path.join(src_dir, '_tmp_b8.bat')
log_path = os.path.join(src_dir, '_tmp_b8.log')

bat_content = f'''\
@echo off
call "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat" >nul 2>&1
cd /d "{src_dir}"
cl /nologo /W3 /O2 /std:c++17 /Fe:08_etw_patch.exe 08_etw_patch.cpp /link kernel32.lib
echo RC=%errorlevel%
'''

with open(bat_path, 'w') as f:
    f.write(bat_content)

with open(log_path, 'w') as logf:
    result = subprocess.run(
        ['cmd.exe', '/c', bat_path],
        stdout=logf, stderr=subprocess.STDOUT,
        cwd=src_dir
    )

with open(log_path, 'r', errors='replace') as f:
    print(f.read())

print('subprocess RC:', result.returncode)
os.remove(bat_path)

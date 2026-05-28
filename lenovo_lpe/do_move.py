import subprocess, os, shutil

src = r'E:\driver_research\lenovo_lpe'
dst = r'E:\Windows-kernel-exploit-research-resource\03_byovd\01_physical-memory-rw\lenovo_lpe'
git_root = r'E:\Windows-kernel-exploit-research-resource'

# List source files to copy
copy_files = [f for f in os.listdir(src)
              if f.endswith('.cpp') or f.endswith('.exe') or f == 'build.bat']

os.makedirs(dst, exist_ok=True)
for fn in sorted(copy_files):
    shutil.copy2(os.path.join(src, fn), os.path.join(dst, fn))
    print(f'  copied: {fn}')

# Check what git sees
result = subprocess.run(
    ['git', 'status', '--short'],
    capture_output=True, text=True, cwd=git_root
)
print('\ngit status:')
print(result.stdout)
print(result.stderr)

@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d E:\driver_research\lenovo_lpe

set FAIL=0
for %%F in (01_kaslr_defeat 02_token_steal 03_ppl_bypass 04_previousmode 05_dse_bypass 06_dkom_hide 07_ioring) do (
    echo [*] Building %%F.exe ...
    cl /nologo /W3 /O2 /std:c++17 %%F.cpp /link kernel32.lib advapi32.lib >nul 2>&1
    if errorlevel 1 ( echo [-] FAILED: %%F & set FAIL=1 ) else ( echo [+] OK     %%F.exe )
)
if %FAIL%==1 ( echo. & echo [!] Some builds failed & exit /b 1 )
echo. & echo [+] All OK

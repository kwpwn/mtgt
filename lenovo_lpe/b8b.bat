@call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
@cd /d E:\driver_research\lenovo_lpe
@cl /nologo /W3 /O2 /std:c++17 /Fe:08_etw_patch.exe 08_etw_patch.cpp /link kernel32.lib >E:\driver_research\lenovo_lpe\b8err.txt 2>&1
@echo exitcode=%errorlevel% >>E:\driver_research\lenovo_lpe\b8err.txt

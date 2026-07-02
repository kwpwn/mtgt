@echo off
setlocal

set BINDIR=%~dp0bin

REM Try to find Visual Studio vcvarsall.bat
set "VCVARS="
for /f "delims=" %%i in ('"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2^>nul') do (
    set "VCVARS=%%i\VC\Auxiliary\Build\vcvarsall.bat"
)

if not defined VCVARS (
    echo [!] MSVC not found. Trying gcc...
    goto :gcc_build
)

echo [*] Using MSVC
call "%VCVARS%" x64 >nul 2>&1
if not exist "%BINDIR%" mkdir "%BINDIR%"

echo [*] Building bindlinks.c
cl /O2 /W3 /Fe:"%BINDIR%\bindlinks.exe" bindlinks.c /link /SUBSYSTEM:CONSOLE
if errorlevel 1 exit /b 1

echo [*] Building utils.c
cl /O2 /W3 /Fe:"%BINDIR%\utils.exe" utils.c /link /SUBSYSTEM:CONSOLE
if errorlevel 1 exit /b 1

echo [*] Building wof_provider.c
cl /O2 /W3 /Fe:"%BINDIR%\wof_provider.exe" wof_provider.c /link /SUBSYSTEM:CONSOLE
if errorlevel 1 exit /b 1

echo [*] Building sync_provider.c
cl /O2 /W3 /Fe:"%BINDIR%\sync_provider.exe" sync_provider.c shlwapi.lib /link /SUBSYSTEM:CONSOLE
if errorlevel 1 exit /b 1

echo [*] Building id_mapper.c
cl /O2 /W3 /Fe:"%BINDIR%\id_mapper.exe" id_mapper.c ntdll.lib /link /SUBSYSTEM:CONSOLE
if errorlevel 1 exit /b 1

echo.
echo [+] Done. Binaries in: %BINDIR%
del *.obj 2>nul
goto :eof

:gcc_build
where gcc >nul 2>&1
if errorlevel 1 (
    echo [x] No C compiler found. Install MSVC or MinGW.
    exit /b 1
)

echo [*] Using GCC
if not exist "%BINDIR%" mkdir "%BINDIR%"

echo [*] Building bindlinks.c
gcc -O2 -Wall -o "%BINDIR%\bindlinks.exe" bindlinks.c -lkernel32
if errorlevel 1 exit /b 1

echo [*] Building utils.c
gcc -O2 -Wall -o "%BINDIR%\utils.exe" utils.c -lkernel32
if errorlevel 1 exit /b 1

echo [*] Building wof_provider.c
gcc -O2 -Wall -o "%BINDIR%\wof_provider.exe" wof_provider.c -lkernel32
if errorlevel 1 exit /b 1

echo [*] Building sync_provider.c
gcc -O2 -Wall -o "%BINDIR%\sync_provider.exe" sync_provider.c -lkernel32 -lshlwapi
if errorlevel 1 exit /b 1

echo [*] Building id_mapper.c
gcc -O2 -Wall -o "%BINDIR%\id_mapper.exe" id_mapper.c -lkernel32 -lntdll
if errorlevel 1 exit /b 1

echo.
echo [+] Done. Binaries in: %BINDIR%

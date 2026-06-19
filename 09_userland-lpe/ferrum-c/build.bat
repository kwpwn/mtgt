@echo off
setlocal

REM ============================================================
REM  Ferrum/C Build Script
REM  Supports MSVC (cl.exe) and MinGW (gcc)
REM ============================================================

set SRC=src\main.c src\common.c ^
    src\modules\services.c ^
    src\modules\tokens.c ^
    src\modules\clsid.c ^
    src\modules\pipes.c ^
    src\modules\dllsearch.c ^
    src\modules\registry.c ^
    src\modules\scheduled.c ^
    src\modules\drivers.c ^
    src\modules\env.c ^
    src\modules\perflib.c ^
    src\modules\comsurrogate.c ^
    src\modules\etw_provider.c ^
    src\modules\objnamespace.c ^
    src\modules\toctou.c ^
    src\modules\print_spooler.c ^
    src\modules\lsa_package.c ^
    src\modules\appcert_dll.c ^
    src\modules\credential_provider.c ^
    src\modules\network_provider.c ^
    src\modules\autorun.c ^
    src\modules\wmi_provider.c ^
    src\modules\alpc_surface.c ^
    src\modules\rpc_endpoint.c ^
    src\modules\driver_ioctl.c ^
    src\modules\impersonate_hunter.c ^
    src\modules\com_autoelevate.c ^
    src\modules\section_audit.c ^
    src\modules\win_msg_surface.c ^
    src\modules\always_install_elevated.c ^
    src\modules\appinit_dll.c ^
    src\modules\uac_bypass_hkcu.c ^
    src\modules\local_service_scan.c ^
    src\modules\wer_handler.c ^
    src\modules\appcompat_sdb.c ^
    src\modules\process_dacl.c ^
    src\modules\dcom_hijack.c ^
    src\modules\shell_handler.c ^
    src\modules\bits_surface.c ^
    src\modules\telemetry_surface.c ^
    src\modules\secondary_logon.c ^
    src\modules\font_provider.c ^
    src\modules\handle_inherit.c ^
    src\modules\dotnet_clr.c ^
    src\modules\com_plus.c ^
    src\modules\ifeo_hijack.c ^
    src\modules\winlogon_plugins.c ^
    src\modules\lsa_notify.c ^
    src\modules\hive_nightmare.c ^
    src\modules\time_provider.c ^
    src\modules\active_setup.c ^
    src\modules\crypto_provider.c ^
    src\modules\ps_hijack.c ^
    src\modules\eap_provider.c ^
    src\modules\vss_writer.c ^
    src\modules\uac_policy.c ^
    src\modules\sysvol_scripts.c

set LIBS_MSVC=advapi32.lib psapi.lib kernel32.lib ntdll.lib rpcrt4.lib ole32.lib oleaut32.lib uuid.lib iphlpapi.lib ws2_32.lib user32.lib
set LIBS_GCC=-ladvapi32 -lpsapi -lntdll -lrpcrt4 -lole32 -luuid -liphlpapi -lws2_32 -luser32

REM ---- Detect MSVC ----
where cl.exe >nul 2>&1
if %ERRORLEVEL% == 0 goto :build_msvc

REM ---- Detect MinGW / GCC ----
where gcc.exe >nul 2>&1
if %ERRORLEVEL% == 0 goto :build_gcc

echo [!] Neither cl.exe nor gcc.exe found in PATH.
echo     Run from a Visual Studio Developer Command Prompt, or install MinGW.
exit /b 1

:build_msvc
echo [*] Building with MSVC...
cl.exe /nologo /W3 /O2 /MT ^
    /D_CRT_SECURE_NO_WARNINGS ^
    /I src ^
    %SRC% ^
    /Fe:ferrum.exe ^
    /link %LIBS_MSVC%
if %ERRORLEVEL% == 0 (
    echo [+] Build successful: ferrum.exe
) else (
    echo [!] MSVC build failed.
)
goto :end

:build_gcc
echo [*] Building with GCC (MinGW)...
gcc -O2 -Wall -Wno-unused-function -municode ^
    -D_WIN32_WINNT=0x0601 -DUNICODE -D_UNICODE ^
    -I src ^
    %SRC% ^
    -o ferrum.exe ^
    %LIBS_GCC%
if %ERRORLEVEL% == 0 (
    echo [+] Build successful: ferrum.exe
) else (
    echo [!] GCC build failed.
)
goto :end

:end
endlocal

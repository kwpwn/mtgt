@echo off
:: build.bat - Build DsArk64 test exe + attack DLL
:: Chạy từ "Developer Command Prompt for VS" (x64)
:: Hoặc chạy vcvarsall.bat x64 trước

setlocal

echo [*] Building test executable...
cl /EHsc /W3 /MT /Ox ^
   dsark64_test.cpp ^
   dsark64_ioctl.cpp ^
   dsark64_crypto.cpp ^
   dsark64_attack.cpp ^
   /link bcrypt.lib ^
   /out:dsark64_test.exe
if errorlevel 1 ( echo [!] Test EXE build FAILED & goto :end )
echo [+] dsark64_test.exe built OK

echo.
echo [*] Building attack DLL...
cl /EHsc /W3 /MT /Ox ^
   dsark64_attack_main.cpp ^
   dsark64_ioctl.cpp ^
   dsark64_crypto.cpp ^
   dsark64_attack.cpp ^
   /LD ^
   /link bcrypt.lib ^
   /DEF:dsark64_attack.def ^
   /out:dsark64_attack.dll
if errorlevel 1 ( echo [!] Attack DLL build FAILED & goto :end )
echo [+] dsark64_attack.dll built OK

echo.
echo [+] Build complete.
echo     dsark64_test.exe  - Run as Admin inside 360 process (or inject first)
echo     dsark64_attack.dll - Inject into 360 process, call DsArk_Init() then DsArk_FullChain()

:end
endlocal

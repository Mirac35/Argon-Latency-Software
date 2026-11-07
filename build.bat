@echo off
setlocal
echo ========================================================
echo   Argon Low Latency Studio v4.0 (2026 Edition) Compiler
echo ========================================================

set CSC="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist %CSC% (
    set CSC="C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"
)

if not exist "bin\Release" mkdir "bin\Release"
if exist "lib\*.dll" (
    copy /Y "lib\*.dll" "bin\Release\" >nul
)

echo.
echo Compiling src\ArgonLatencyStudio.cs to bin\Release\ArgonLatencyStudio.exe...
%CSC% /target:winexe /optimize+ /platform:x64 /r:"lib\LibreHardwareMonitorLib.dll" /out:"bin\Release\ArgonLatencyStudio.exe" "src\ArgonLatencyStudio.cs"

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Build failed with exit code %ERRORLEVEL%!
    exit /b %ERRORLEVEL%
)

copy /Y "bin\Release\ArgonLatencyStudio.exe" "bin\Release\Argon_UltraLowLatency_v4.0.exe" >nul 2>&1
copy /Y "bin\Release\ArgonLatencyStudio.exe" "bin\Release\Argon_UltraLowLatency_v3.8.exe" >nul 2>&1

echo.
echo [SUCCESS] Build completed with 0 errors!
echo Executable: %~dp0bin\Release\ArgonLatencyStudio.exe
echo Executable: %~dp0bin\Release\Argon_UltraLowLatency_v4.0.exe
endlocal

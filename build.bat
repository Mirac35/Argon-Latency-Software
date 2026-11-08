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
    copy /Y "lib\*.dll" "bin\Release\" >nul 2>&1
)
if exist "app.ico" (
    copy /Y "app.ico" "bin\Release\" >nul 2>&1
)

set OUT_EXE=bin\Release\Argon_UltraLowLatency_v4.0.exe

:: If the target EXE is locked by a running instance, rename it aside so CSC can write a fresh binary
if exist "%OUT_EXE%.old" del /f /q "%OUT_EXE%.old" >nul 2>&1
if exist "%OUT_EXE%" (
    del /f /q "%OUT_EXE%" >nul 2>&1
    if exist "%OUT_EXE%" (
        move /y "%OUT_EXE%" "%OUT_EXE%.old" >nul 2>&1
    )
)

echo.
echo Compiling src\ArgonLatencyStudio.cs to %OUT_EXE%...
%CSC% /target:winexe /optimize+ /platform:x64 /win32icon:"app.ico" /r:"lib\LibreHardwareMonitorLib.dll" /out:"%OUT_EXE%" "src\ArgonLatencyStudio.cs"

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Build failed with exit code %ERRORLEVEL%!
    exit /b %ERRORLEVEL%
)

echo.
echo [SUCCESS] Build completed with 0 errors!
echo Executable: %~dp0%OUT_EXE%
endlocal

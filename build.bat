@echo off
setlocal
echo ========================================================
echo   Argon Low Latency Studio - Fast Standalone Compiler
echo ========================================================
echo.

set CSC_PATH=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe

if not exist "%CSC_PATH%" (
    echo [ERROR] csc.exe could not be found at:
    echo %CSC_PATH%
    echo Please ensure .NET Framework 4.0+ is installed.
    echo.
    pause
    exit /b 1
)

if not exist "bin\Release" (
    mkdir "bin\Release"
)

echo Compiling src\ArgonLatencyStudio.cs to bin\Release\Argon_UltraLowLatency_v3.8.exe...
"%CSC_PATH%" /target:winexe /platform:x64 /optimize+ /out:"bin\Release\Argon_UltraLowLatency_v3.8.exe" /r:System.dll /r:System.Core.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll /r:System.Management.dll "src\ArgonLatencyStudio.cs"

if %ERRORLEVEL% equ 0 (
    echo.
    echo ========================================================
    echo   [SUCCESS] Build succeeded!
    echo   Output: bin\Release\Argon_UltraLowLatency_v3.8.exe
    echo ========================================================
) else (
    echo.
    echo [ERROR] Build failed with exit code %ERRORLEVEL%!
)
echo.
pause

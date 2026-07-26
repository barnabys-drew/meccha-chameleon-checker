@echo off
REM ===================================================================
REM  Meccha Chameleon Workshop malware checker
REM
REM  Double-click this file to check your PC.
REM
REM  This only LOOKS at your computer and tells you what it finds.
REM  It never deletes, moves or changes anything.
REM
REM  All it does is start scan-windows.ps1, which sits next to this
REM  file and which you are welcome to read first.
REM ===================================================================

setlocal
cd /d "%~dp0"

if not exist "scan-windows.ps1" (
    echo.
    echo   ERROR: scan-windows.ps1 was not found next to this file.
    echo   Please keep all the downloaded files together in one folder.
    echo.
    pause
    exit /b 2
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "scan-windows.ps1" %*
set RESULT=%ERRORLEVEL%

echo.
echo   Press any key to close this window.
pause >nul
exit /b %RESULT%

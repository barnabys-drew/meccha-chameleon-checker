@echo off
REM ===================================================================
REM  Meccha Chameleon Workshop malware checker - DEEP scan
REM
REM  Double-click this for a more thorough check.
REM
REM  The normal check (check-my-pc.bat) looks for the exact malware
REM  researchers have published. This one ALSO looks for files that
REM  merely behave like it, which can catch a repackaged copy nobody
REM  has reported yet.
REM
REM  Because of that, it can point at innocent files. Anything it
REM  finds is worth a look, NOT proof that you are infected. It still
REM  never deletes, moves or changes anything.
REM
REM  Tip: right-click this file and choose "Run as administrator" to
REM  also let it check Windows' own record of what has run.
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

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "scan-windows.ps1" -Deep %*
set RESULT=%ERRORLEVEL%

echo.
echo   Press any key to close this window.
pause >nul
exit /b %RESULT%

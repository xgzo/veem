@echo off
setlocal
cd /d "%~dp0"
title veem - HTTP Config Auditor
where py >nul 2>nul
if not errorlevel 1 (
    py -3 veem.py %*
    goto done
)
where python >nul 2>nul
if not errorlevel 1 (
    python veem.py %*
    goto done
)
echo [ERROR] Python was not found. Install Python 3.10+ and enable Add to PATH.
:done
echo.
echo Session finished. Any error message is shown above.
pause
endlocal

@echo off
rem Windows: double-click to start the GenAI Guardrail Gateway (opens the browser when ready).
setlocal
cd /d "%~dp0"
title GenAI Guardrail Gateway

py -3.12 -c "import sys" >nul 2>&1
if %errorlevel%==0 ( set "PY=py -3.12" & goto run )
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if %errorlevel%==0 ( set "PY=py -3" & goto run )
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if %errorlevel%==0 ( set "PY=python" & goto run )

echo Python 3.10 or newer is not installed.
where winget >nul 2>&1
if errorlevel 1 goto manual
choice /m "Install Python 3.12 now with winget"
if errorlevel 2 goto manual
winget install -e --id Python.Python.3.12 --accept-package-agreements --accept-source-agreements
echo.
echo Python was installed. Close this window and double-click this file again.
pause
exit /b 0

:manual
echo Install Python 3.12 from https://www.python.org/downloads/windows/
echo (tick "Add python.exe to PATH"), then double-click this file again.
pause
exit /b 1

:run
%PY% launcher.py %*
if errorlevel 1 pause

@echo off
cd /d "%~dp0"
title Phish X

rem Check the venv exists – prompt to install if not
if not exist "venv\Scripts\python.exe" (
    echo Phish X is not installed yet.
    echo Please run "install.cmd" first.
    pause
    exit /b 1
)

echo Starting Phish X...
venv\Scripts\python.exe run_web.py
if errorlevel 1 (
    echo.
    echo Phish X exited with an error. Check output above.
    pause
)

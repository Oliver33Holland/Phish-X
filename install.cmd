@echo off
cd /d "%~dp0"

echo ============================================
echo   Phish X - Installation
echo ============================================
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

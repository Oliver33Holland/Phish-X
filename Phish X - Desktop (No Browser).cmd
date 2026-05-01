@echo off
cd /d "%~dp0"
title Phish X
rem Desktop app: opens in its own window. Does NOT open a browser.
venv\Scripts\python.exe phishx_app.py
if errorlevel 1 pause

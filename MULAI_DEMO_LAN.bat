@echo off
setlocal
cd /d "%~dp0"
title WIB SES Group - Mode Demo (LAN)
if not exist ".venv\Scripts\python.exe" (
 py -3 -m venv .venv 2>nul
 if errorlevel 1 python -m venv .venv
)
if not exist ".venv\Scripts\python.exe" (
 echo Python tidak ditemukan.
 pause
 exit /b 1
)
if not exist ".venv\installed.ok" (
 echo Memasang paket aplikasi...
 ".venv\Scripts\python.exe" -m pip install -r requirements.txt
 if errorlevel 1 (pause & exit /b 1)
 echo OK>".venv\installed.ok"
)
echo Membuka mode DEMONSTRASI (data contoh terpisah)...
".venv\Scripts\python.exe" launcher.py demo lan
pause

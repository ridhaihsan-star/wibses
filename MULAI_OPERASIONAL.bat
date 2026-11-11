@echo off
setlocal
cd /d "%~dp0"
title WIB SES Group - Aplikasi Operasional
if not exist ".venv\Scripts\python.exe" (
 echo Menyiapkan lingkungan aplikasi...
 py -3 -m venv .venv 2>nul
 if errorlevel 1 python -m venv .venv
)
if not exist ".venv\Scripts\python.exe" (
 echo Python belum ditemukan. Pasang Python 3.11 atau lebih baru dari python.org.
 pause
 exit /b 1
)
if not exist ".venv\installed.ok" (
 echo Memasang paket aplikasi. Diperlukan internet saat instalasi pertama.
 ".venv\Scripts\python.exe" -m pip install -r requirements.txt
 if errorlevel 1 (
  echo Instalasi paket gagal. Periksa internet dan jalankan kembali.
  pause
  exit /b 1
 )
 echo OK>".venv\installed.ok"
)
echo.
echo Membuka aplikasi WIB-SES Group (DATA OPERASIONAL)...
".venv\Scripts\python.exe" launcher.py operasional
pause

@echo off
:: Membuka port 8765 di Windows Firewall (hanya jaringan Private) agar rekan
:: di Wi-Fi kantor yang sama bisa membuka aplikasi WIB x SES Group.
net session >nul 2>&1
if errorlevel 1 (
 echo Meminta izin Administrator...
 powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
 exit /b
)
title Buka akses Wi-Fi - WIB SES Group
netsh advfirewall firewall delete rule name="WIB SES Group 8765" >nul 2>&1
netsh advfirewall firewall add rule name="WIB SES Group 8765" dir=in action=allow protocol=TCP localport=8765 profile=private
if errorlevel 1 (
 echo GAGAL membuat aturan firewall.
) else (
 echo.
 echo BERHASIL. Port 8765 dibuka untuk jaringan Private ^(Wi-Fi kantor^).
 echo Rekan dapat membuka alamat berikut dari Wi-Fi yang sama:
 for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4"') do for /f "tokens=*" %%b in ("%%a") do echo    http://%%b:8765/
)
echo.
pause

@echo off
rem Diagnostico de SOLO LECTURA del USB. Pide permisos de administrador (UAC).
rem El resultado queda en diagnostico_usb.txt en esta misma carpeta.
cd /d "%~dp0"
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Construir\Diagnosticar-USB.ps1" -Salida "%~dp0diagnostico_usb.txt"
echo.
echo Listo. Puede cerrar esta ventana.
timeout /t 15 >nul

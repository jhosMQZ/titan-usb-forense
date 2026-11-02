@echo off
rem ==================================================================
rem  Repara la particion TITAN-USB (chkdsk) y borra las carpetas danadas
rem  que quedaron en Casos. Pide escribir REPARAR. No toca las herramientas.
rem ==================================================================
cd /d "%~dp0"
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Construir\Reparar-Respaldos.ps1"
echo.
echo Terminado. Revise los mensajes de arriba.
pause

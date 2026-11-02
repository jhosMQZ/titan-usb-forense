@echo off
rem Prueba en este PC el reporte y la lectura de diskpart (solo lectura).
cd /d "%~dp0"
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Construir\Probar-TITAN.ps1"
echo.
echo Prueba terminada. Revise el resultado.
pause

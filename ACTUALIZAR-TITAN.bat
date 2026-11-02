@echo off
rem ==================================================================
rem  Actualiza el USB TITAN con los scripts corregidos de esta carpeta
rem  y vuelve a sellar su ancla (NO borra la memoria ni sus respaldos).
rem  Pide permisos de administrador (UAC).
rem ==================================================================
cd /d "%~dp0"
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
echo Paso previo: revisando la sintaxis de todos los scripts del kit...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Construir\Verificar-Sintaxis.ps1"
if errorlevel 1 (
  echo.
  echo Hay errores de sintaxis: NO se toco la memoria. Ver sintaxis_errores.txt
  pause
  exit /b 1
)
echo.
echo Compilando el motor de TITAN BLACKBOX si hace falta...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Construir\Compilar-Rescate.ps1" -SiHaceFalta
if errorlevel 1 (
  echo.
  echo No se pudo compilar el motor: NO se toco la memoria.
  pause
  exit /b 1
)
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Construir\Actualizar-Ancla.ps1"
echo.
echo Proceso terminado. Revise los mensajes de arriba.
pause
exit /b

@echo off
rem Reorganiza una memoria USB en una sola carpeta (ARCHIVOS), la renombra a TITAN-USB y la prueba.
rem No borra archivos tuyos. Deja un registro para deshacer. Pide permisos de administrador (UAC).
cd /d "%~dp0"
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
set "LETRA="
set /p LETRA=Letra de la memoria USB a organizar (ejemplo: E): 
if "%LETRA%"=="" (
  echo No se indico ninguna letra. No se hizo nada.
  pause
  exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Construir\Organizar-USB.ps1" -Letra %LETRA% -Carpeta ARCHIVOS -Etiqueta TITAN-USB
echo.
echo Listo. Puede cerrar esta ventana.
pause >nul

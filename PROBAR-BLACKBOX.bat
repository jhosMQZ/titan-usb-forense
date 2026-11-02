@echo off
rem ==================================================================
rem  Pruebas de TITAN BLACKBOX en este PC con DISCOS VIRTUALES desechables.
rem  No toca ningun disco real ni la USB. Resultado: prueba_blackbox.txt
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
  echo Hay errores de sintaxis. Ver sintaxis_errores.txt
  pause
  exit /b 1
)
echo.
echo  AVISO: durante la prueba Windows puede mostrar "Debe formatear el disco
echo  en la unidad X: antes de usarlo". Es un disco VIRTUAL de prueba:
echo  pulse CANCELAR. No formatee nada.
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Construir\Probar-Blackbox.ps1"
echo.
echo Pruebas terminadas. Revise el resultado.
pause

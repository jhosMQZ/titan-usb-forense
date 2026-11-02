@echo off
rem ==================================================================
rem  Comprueba que cada archivo del ultimo respaldo de TITAN es identico
rem  al original (SHA-256 contra el inventario). SOLO LEE la USB.
rem  Resultado: verificacion_respaldo_<caso>.txt y .csv en esta carpeta.
rem ==================================================================
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Construir\Verificar-Respaldo.ps1"
echo.
echo Verificacion terminada. Revise el resultado.
pause

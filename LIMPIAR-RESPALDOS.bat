@echo off
rem ==================================================================
rem  Deja la USB TITAN limpia para otro equipo: borra los casos de la
rem  particion TITAN-USB (pide escribir BORRAR). No toca las herramientas.
rem ==================================================================
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Construir\Limpiar-Respaldos.ps1"
echo.
echo Terminado. Revise los mensajes de arriba.
pause

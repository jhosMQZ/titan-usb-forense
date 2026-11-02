@echo off
rem ==================================================================
rem  Crea el USB forense TITAN (BORRA la memoria USB elegida).
rem  Requiere: Windows ADK + complemento WinPE instalados.
rem  Pide permisos de administrador (UAC).
rem ==================================================================
cd /d "%~dp0"
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
if not exist "%ProgramFiles(x86)%\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\DandISetEnv.bat" goto faltaadk
if not exist "%ProgramFiles(x86)%\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\WinPE_OCs" goto faltaadk
if not exist "%~dp0Descargas\clamav-1.5.4.win.x64.zip" (
  echo Falta Descargas\clamav-1.5.4.win.x64.zip
  pause
  exit /b 1
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
  echo No se pudo compilar el motor: NO se toco la memoria.
  pause
  exit /b 1
)
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Construir\Crear-USB.ps1" -ClamAVZip "%~dp0Descargas\clamav-1.5.4.win.x64.zip" -ClamAVSha256 0D9E0228B2674137EA1A2853566C98A0278AD52AB2582C3D6DBD75373848C395 -PermitirClamAVSinFirma -Nombre TITAN
echo.
echo Proceso terminado. Revise los mensajes de arriba.
pause
exit /b
:faltaadk
echo.
echo FALTA el Windows ADK y/o su complemento WinPE.
echo Se abrira la pagina oficial de Microsoft. Instale los DOS:
echo   1) "Windows ADK"  (marque solo "Deployment Tools")
echo   2) "Windows PE add-on for the ADK"
echo Luego vuelva a ejecutar este archivo.
start "" "https://learn.microsoft.com/windows-hardware/get-started/adk-install"
pause
exit /b 1

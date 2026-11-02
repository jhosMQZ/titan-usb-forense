@echo off
rem ======================================================================
rem  startnet.cmd - se ejecuta al arrancar WinPE (va dentro de boot.wim,
rem  en X:\Windows\System32\startnet.cmd). Lo instala Crear-USB.ps1.
rem ======================================================================
rem Inicializacion SIN red y con firewall activo (ver X:\Ancla\unattend.xml)
X:\Windows\System32\wpeinit.exe -unattend:X:\Ancla\unattend.xml
rem Si el archivo de respuestas fallara, se inicializa igual (dispositivos) con firewall activo
if errorlevel 1 X:\Windows\System32\wpeinit.exe
X:\Windows\System32\wpeutil.exe EnableFirewall >nul 2>&1
rem Teclado espanol (Latinoamerica). Para EE.UU. use 0409:00000409
X:\Windows\System32\wpeutil.exe SetKeyboardLayout 240a:0000080a >nul 2>&1
rem Plan de energia de alto rendimiento (el analisis dura horas)
X:\Windows\System32\powercfg.exe /s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c >nul 2>&1
cls
echo Iniciando USB forense...
X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File X:\Ancla\Iniciar.ps1
echo.
echo Para volver al menu escriba:
echo   powershell -NoProfile -ExecutionPolicy Bypass -File X:\Ancla\Iniciar.ps1
